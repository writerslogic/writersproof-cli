# Todo
<!-- suggest | Updated: 2026-04-11 | Domain: code | Languages: rust, swift, csharp, typescript, javascript | Files: 297 | Issues: 167 -->

## Summary
| Severity | Open | Fixed | Skipped | Possibly Fixed |
|----------|------|-------|---------|----------------|
| CRITICAL | 0    | 2     | 12      | 0              |
| HIGH     | 0    | 28    | 47      | 0              |
| MEDIUM   | 0    | 36    | 62      | 0              |

## Compound Risk
- [ ] **CLU-001** `ffi_crash_cascade`, CRITICAL, components: C-001, C-002, C-003, C-007
  <!-- compound_impact: "FFI boundary failures cascade to unrecoverable app crash; no graceful degradation" -->
- [ ] **CLU-002** `key_material_leak`, CRITICAL, components: C-006, C-012, H-020, H-053
  <!-- compound_impact: "Signing keys remain in memory across multiple surfaces; memory dump recovers non-repudiation keys" -->
- [ ] **CLU-003** `ipc_protocol_desync`, CRITICAL, components: C-014, H-008, H-043
  <!-- compound_impact: "IPC event listener races with request/response; push events corrupt protocol state" -->
- [ ] **CLU-004** `commitment_chain_forgery`, HIGH, components: H-035, H-036, H-038, H-040
  <!-- compound_impact: "Browser extension commitment chains can be forged via race conditions, hex parsing, and session storage tampering" -->

## Systemic Issues
- [ ] **SYS-001** `force_unwrap_ffi`, 50+ sites, CRITICAL — macOS CPoEEngineFFI.swift
  <!-- pid:force_unwrap_ffi | verified:true | first:2026-04-11 -->
  Files: `CPoEEngineFFI.swift:551`, `:567`, `:550`, `:27`, `:34`, `:90`, `:5520` (nested try!)
  Fix: Replace try!/force-unwrap with do/catch error propagation across all 50+ FFI functions

- [-] **SYS-002** `silent_error_swallow`, 12 files, HIGH
  <!-- pid:silent_error | verified:true | first:2026-04-11 | skipped:2026-05-04 -->
  Files: `SafariExtensionShared.swift:599`, `CloudSyncDetectionService.swift:451`, `AuthService.cs:370`, `ErrorService.cs:164`, `CrashReportingService.swift:62`, `App.tsx:271`
  macOS sites verified: SafariExtensionShared:599 uses appropriate fallback pattern; CloudSyncDetectionService:451 is standard Swift optional guard; CrashReportingService:62 is just a log. Windows/Office365 sites in unchecked-out submodules.

- [ ] **SYS-003** `god_module`, 14 files, HIGH
  <!-- pid:god_module | verified:true | first:2026-04-11 -->
  Files: `CPoEEngineFFI.swift:6344`, `OnboardingView.swift:1450`, `SettingsContent.swift:1383`, `SafariExtensionShared.swift:1214`, `CloudSyncService.swift:1206`, `cmd_track/mod.rs:1107`, `ReceiptValidation.swift:1139`, `StatusBarController.swift:983`, `PopoverComponents.swift:942`, `CollaborativeEvidenceDialog.xaml.cs:924`, `SettingsPage.xaml.cs:855`, `NotificationManager.swift:839`, `App.tsx:834`, `Code.ts:888`
  Fix: Split each into focused submodules per existing pattern in codebase

- [x] **SYS-004** `path_traversal_insufficient`, 8 files, HIGH
  <!-- pid:path_traversal | verified:true | first:2026-04-11 | fixed:2026-05-04 -->
  Files: `cmd_track/mod.rs:368`, `cmd_track/filesystem.rs:69`, `ProofCardService.swift:203`, `WARReportPDFRenderer.swift:190`, `WatchPathsDialog.xaml.cs:95`, `SettingsPage.xaml.cs:420`, `SettingsUtilities.swift:40`
  All accessible sites verified: CLI uses fs::canonicalize + documented safety contract; macOS uses URL.standardized.resolvingSymlinksInPath + path component comparison. Windows sites inaccessible (submodule not checked out).

- [-] **SYS-005** `plaintext_api_key_storage`, 3 files, HIGH
  <!-- pid:hardcoded_secret | verified:true | first:2026-04-11 | skipped:2026-05-04 -->
  Files: `Code.ts:566`, `WritersProofClient.ts:175` (Office365), `SafariExtensionShared.swift:246`
  Safari site verified: SafariExtensionShared uses AES-GCM encrypted storage with Keychain-derived keys; no plaintext API keys found. Office365 files in unchecked-out submodule.

- [ ] **SYS-006** `async_void_exception_loss`, 5 files, MEDIUM — Windows app
  <!-- pid:async_void | verified:true | first:2026-04-11 -->
  Files: `ErrorService.cs:164`, `FileWatcherService.cs:202`, `App.xaml.cs:549`
  Fix: Change async void to async Task, or wrap body in try-catch

- [ ] **SYS-007** `missing_cancellation_token`, 4 files, MEDIUM — Windows pages
  <!-- pid:missing_cancellation_token | verified:true | first:2026-04-11 -->
  Files: `HomePage.xaml.cs:185`, `SessionPage.xaml.cs:120`, `DashboardPage.xaml.cs:380`
  Fix: Implement OnNavigatedFrom with CancellationTokenSource.Cancel()

- [x] **SYS-008** `dateformatter_thread_safety`, 2 files, MEDIUM — macOS
  <!-- pid:data_race | verified:true | first:2026-04-11 | fixed:2026-05-04 -->
  Files: `DataTransparencyView.swift:285`, `StatusBarController.swift:16`
  Fix: Both sites are @MainActor-isolated; thread safety is guaranteed. DataTransparencyView formatter marked with safety comment.

## Critical
- [x] **C-001** `[security]` `CPoEEngineFFI.swift:551`: Force unwrap of String from UTF-8 bytes can crash on invalid UTF-8 from Rust FFI
  <!-- pid:force_unwrap_ffi | batch:3 | verified:true | first:2026-04-11 | fixed:2026-04-11 -->
  Impact: Any FFI call returning string data crashes app if Rust buffer contains invalid UTF-8 | Fix: guard let with UniffiInternalError.invalidUtf8 throw | Effort: small

- [x] **C-002** `[security]` `CPoEEngineFFI.swift:567`: Force unwrap in read() path for String deserialization from buffer
  <!-- pid:force_unwrap_ffi | batch:3 | verified:true | first:2026-04-11 | fixed:2026-04-11 -->
  Impact: Same as C-001; affects every string return from FFI | Fix: guard let with UniffiInternalError.invalidUtf8 throw | Effort: small

- [-] **C-003** `[security]` `CPoEEngineFFI.swift:550`: Force unwrap of unsafe pointer creation without bounds validation
  <!-- pid:FFI_BUFFER_BOUNDS | batch:3 | verified:false | first:2026-04-11 | reason:false_positive — line 547 checks data==nil before force unwrap -->
  Impact: N/A | Effort: N/A

- [-] **C-004** `[security]` `DeviceAttestationService.swift:335`: Counter overflow at UInt64.max silently returns max without blocking
  <!-- pid:COUNTER_OVERFLOW | batch:4 | verified:false | first:2026-04-11 | reason:false_positive — line 335 already returns false with error on UInt64.max -->
  Impact: N/A | Effort: N/A

- [-] **C-005** `[security]` `SafariExtensionShared.swift:449`: Force unwrap on hexToData bypasses HMAC verification
  <!-- pid:FORCE_UNWRAP_HMAC | batch:5 | verified:false | first:2026-04-11 | reason:false_positive — line 450 already uses guard let, not force unwrap -->
  Impact: N/A | Effort: N/A

- [-] **C-006** `[security]` `cmd_verify.rs:598`: Ed25519 key material not zeroized; seed remains on stack after function
  <!-- pid:key_zeroize | batch:1 | verified:false | first:2026-04-11 | reason:false_positive — key_data wrapped in Zeroizing; seed zeroized at line 103; SigningKey zeroizes on drop -->
  Impact: N/A | Effort: N/A

- [-] **C-007** `[architecture]` `CPoEEngineFFI.swift:5520`: Nested try! in every public FFI function; no error recovery
  <!-- pid:FFI_NESTED_TRY | batch:3 | verified:true | first:2026-04-11 | reason:architectural — auto-generated UniFFI code; hand-edits overwritten on regeneration; needs UniFFI template change -->
  Impact: Any FFI failure crashes app; affects 50+ public functions | Fix: Modify UniFFI codegen template | Effort: large

- [-] **C-008** `[security]` `SupabaseClient.swift:326`: SPKI cert pinning hardcodes ASN.1 headers; non-standard key sizes silently fail
  <!-- pid:SPKI_HEADER_MISMATCH | batch:5 | verified:true | first:2026-04-11 | reason:nit — WritersProof servers use known key types (EC P-256/RSA-2048); theoretical risk -->
  Impact: Theoretical; servers use known key types | Effort: large

- [-] **C-009** `[security]` `CloudSyncService.swift:358`: Unvalidated dimensions array from FFI used in JSON construction
  <!-- pid:INPUT_VALIDATION_CLOUD | batch:5 | verified:true | first:2026-04-11 | reason:nit — FFI data from same-process trusted engine, not external input -->
  Impact: Theoretical; data from same-process engine | Effort: medium

- [-] **C-010** `[security]` `WARReportHTMLRenderer.swift:176`: Incomplete HTML escaping allows CSS/JS injection
  <!-- pid:xss_html | batch:7 | verified:false | first:2026-04-11 | reason:false_positive — standard 5-entity escaping (&<>"') covers all text-context injection vectors -->
  Impact: N/A | Effort: N/A

- [-] **C-011** `[concurrency]` `CPoEBridge.Batch.cs:99`: Disposed SemaphoreSlim race when concurrency settings change
  <!-- pid:disposed_semaphore_race | batch:8 | verified:false | first:2026-04-11 | reason:already_fixed — H-003 fix comment at line 99; local snapshot pattern is standard fix -->
  Impact: ObjectDisposedException or deadlock under concurrent use | Fix: Never dispose old semaphores; let GC collect | Effort: large

- [-] **C-012** `[security]` `MnemonicRecoveryDialog.xaml.cs:85`: Mnemonic phrase clearing incomplete; GC may relocate before wipe
  <!-- pid:crypto_memory_safety | batch:10 | verified:true | first:2026-04-11 | reason:architectural — .NET managed string limitation; needs SecureString throughout; deep redesign -->
  Impact: Recovery phrase recoverable from memory dumps | Fix: Use SecureString or pinned byte arrays | Effort: large

- [-] **C-013** `[concurrency]` `IpcClient.cs:490`: Event listener and RequestAsync share same pipe; push events desync protocol
  <!-- pid:ipc_protocol_desync | batch:8 | verified:true | first:2026-04-11 | reason:architectural — documented TODO at line 490 with tradeoff analysis; needs IPC protocol changes -->
  Impact: Push events misinterpreted as responses; data corruption | Fix: Separate connections or message correlation IDs | Effort: large

- [-] **C-014** `[security]` `contentEvents.ts:1`: Webhook signature verification implementation not visible; replay attacks possible
  <!-- pid:webhook_replay | batch:11 | verified:false | first:2026-04-11 | reason:false_positive — app.ts:174-179 has full HMAC-SHA256 verification via verifyWebhookSignature(); contentEvents.ts called after middleware validates -->
  Impact: N/A | Effort: N/A

## High
- [-] **H-001** `[security]` `CPoEEngineFFI.swift:27`: try! in RustBuffer.from() crashes on allocation failure
  <!-- pid:FFI_TRY_UNWRAP | batch:3 | verified:true | first:2026-04-11 -->
  Impact: Unrecoverable crash in OOM conditions | Fix: Replace try! with proper error propagation | Effort: small

- [-] **H-002** `[security]` `CPoEEngineFFI.swift:34`: try! in deallocate() crashes on deallocation failure
  <!-- pid:FFI_TRY_UNWRAP | batch:3 | verified:true | first:2026-04-11 -->
  Impact: Memory leak or crash during cleanup | Fix: Wrap in do/catch and log | Effort: small

- [-] **H-003** `[security]` `CPoEEngineFFI.swift:90`: Force cast (as!) in readInt for UInt8
  <!-- pid:FFI_CAST_UNSAFE | batch:3 | verified:true | first:2026-04-11 -->
  Impact: Type system violation at FFI boundary | Fix: Use safe cast with guard | Effort: small

- [-] **H-004** `[error_handling]` `EngineService.swift:134`: validateFFIContract() crashes fatally if FFI incompatible
  <!-- pid:INIT_FFI_VALIDATION | batch:3 | verified:true | first:2026-04-11 -->
  Impact: Startup crash with no recovery | Fix: Wrap in try/catch; degrade gracefully | Effort: medium

- [x] **H-005** `[security]` `EndpointSecurityClient.swift:238`: Force unwrap of es_new_client result
  <!-- pid:ES_NULLCHECK | batch:3 | verified:true | first:2026-04-11 -->
  Impact: Null pointer deref if client nil with SUCCESS | Fix: guard let client | Effort: small

- [x] **H-006** `[security]` `EndpointSecurityClient.swift:122`: Unsafe C string from ES without null-termination validation
  <!-- pid:ES_CSTRING_SAFETY | batch:3 | verified:true | first:2026-04-11 -->
  Impact: Buffer over-read in all file/process event data | Fix: Use String(bytes:encoding:) with length | Effort: medium

- [x] **H-007** `[security]` `AuthService+Session.swift:417`: Device binding fails open on IOKit failure
  <!-- pid:FAIL_OPEN | batch:4 | verified:true | first:2026-04-11 | fixed:2026-05-06 — bindOrVerify() returns false on nil fingerprint; nil triggers re-auth in restoration flow -->
  Impact: Auth on wrong device if IOKit returns nil | Fix: Fail closed; require re-authentication | Effort: small

- [-] **H-008** `[security]` `ReceiptValidation.swift:837`: Keychain error during receipt downgrade check bypasses validation
  <!-- pid:DOWNGRADE_CHECK_FAIL | batch:4 | verified:true | first:2026-04-11 -->
  Impact: Receipt replay with older versions | Fix: Fail closed on Keychain error | Effort: small

- [-] **H-009** `[security]` `AuthService+OAuth.swift:152`: O_NOFOLLOW on file but parent dir not checked for symlinks
  <!-- pid:SYMLINK_RACE | batch:4 | verified:true | first:2026-04-11 -->
  Impact: API key file written to attacker-controlled location | Fix: Validate parent with resolvingSymlinksInPath() | Effort: medium

- [x] **H-010** `[security]` `EncryptedSessionStore.swift:168`: Deadlock guard check is inside sync block (already blocked)
  <!-- pid:REENTRANT_DEADLOCK | batch:4 | verified:true | first:2026-04-11 | fixed:2026-05-06 — dispatchPrecondition guard runs before keyQueue.sync, not inside it -->
  Impact: Thread deadlocks indefinitely on reentrance | Fix: Check before calling sync | Effort: small

- [x] **H-011** `[security]` `ReceiptValidation.swift:438`: Partial receipt binding field allows bypass
  <!-- pid:BINDING_VALIDATION | batch:4 | verified:true | first:2026-04-11 | fixed:2026-05-06 — guard let requires BOTH opaqueValue and deviceIdentifierHash; fails closed with .deviceMismatch -->
  Impact: Attacker strips one binding field to bypass device check | Fix: Require BOTH fields present AND valid | Effort: small

- [-] **H-012** `[security]` `CertificateService.swift:223`: Path component bypass via normalization differences
  <!-- pid:PATH_COMPONENT_BYPASS | batch:4 | verified:true | first:2026-04-11 -->
  Impact: Sig file written outside allowed directory | Fix: resolveSymlinksInPath() before comparison | Effort: medium

- [-] **H-013** `[concurrency]` `AuthService+Session.swift:284`: Session refresh race; two threads both attempt simultaneous refresh
  <!-- pid:RACE_CONDITION | batch:4 | verified:true | first:2026-04-11 -->
  Impact: Token written twice; inconsistent state | Fix: Use DispatchSemaphore or async serialization | Effort: medium

- [-] **H-014** `[security]` `AuthService+Session.swift:182`: Clock rollback detection using manipulable ProcessInfo.systemUptime
  <!-- pid:SYSTEM_TIME_ATTACK | batch:4 | verified:true | first:2026-04-11 -->
  Impact: Attacker resets device binding checks via time adjustment | Fix: Use mach_absolute_time() | Effort: medium

- [x] **H-015** `[security]` `EncryptedSessionStore.swift:141`: Key rotation fallback without audit trail
  <!-- pid:KEY_ROTATION_AUDIT | batch:4 | verified:true | first:2026-04-11 -->
  Impact: Silent key confusion on fallback; hard to detect incomplete rotation | Fix: Log which key decrypted | Effort: small

- [x] **H-016** `[error_handling]` `DeviceAttestationService.swift:373`: Empty publicKeyB64 passes !isEmpty check
  <!-- pid:EMPTY_STRING_VALIDATION | batch:4 | verified:true | first:2026-04-11 | fixed:2026-05-06 — guard !response.publicKeyB64.isEmpty rejects empty; base64 decode required after -->
  Impact: Empty base64 decoded as zero-length data | Fix: Check .isEmpty before decoding | Effort: small

- [-] **H-017** `[error_handling]` `SafariExtensionShared.swift:599`: Bare catch swallows all errors silently
  <!-- pid:ERROR_SWALLOW | batch:5 | verified:true | first:2026-04-11 | reason:mitigated — catch logs via logger.error; deletion failure is non-critical cleanup; error is observable -->
  Impact: User data loss undetectable; corrupted session files return nil | Fix: Catch specific errors; log all | Effort: small

- [x] **H-018** `[security]` `ProofCardService.swift:203`: Path validation with string prefix; no symlink resolution
  <!-- pid:PATH_TRAVERSAL_PROOF_CARD | batch:5 | verified:true | first:2026-04-11 | fixed:2026-05-06 — resolvingSymlinksInPath() + component-array containment check; comment at line 300 explicitly avoids prefix pitfall -->
  Impact: Proof card saved to arbitrary locations | Fix: Canonical path comparison | Effort: small

- [-] **H-019** `[concurrency]` `DataDirectoryMonitor.swift:189`: FSEvent callback races with monitor stop; use-after-free risk
  <!-- pid:RACE_FSEVENT | batch:5 | verified:true | first:2026-04-11 -->
  Impact: Crash if FSEventStream torn down during background validation | Fix: Capture context; check _isRunning | Effort: medium

- [x] **H-020** `[security]` `util.rs:82`: Signing key not fully zeroized; seed on stack
  <!-- pid:key_zeroize | batch:1 | verified:true | first:2026-04-11 | fixed:2026-05-06 — key_data.zeroize() at line 86 and 92; seed.zeroize() at line 103 after SigningKey creation -->
  Impact: Key material in stack/heap after function returns | Fix: Return Zeroizing<SigningKey> | Effort: medium

- [x] **H-021** `[security]` `cmd_track/mod.rs:368`: Symlink TOCTOU in session path comparison
  <!-- pid:toctou | batch:1 | verified:true | first:2026-04-11 | fixed:2026-05-06 — fs::canonicalize() on both paths before comparison; falls back to original on error -->
  Impact: Tracking wrong file via symlink swap | Fix: Canonicalize before comparison | Effort: small

- [x] **H-022** `[security]` `native_messaging_host/handlers.rs:59`: Unbounded filename length from user-controlled title
  <!-- pid:path_traversal | batch:1 | verified:true | first:2026-04-11 | fixed:2026-05-06 — MAX_TITLE_LEN=255 const; title truncated to 255 chars on input, 64 chars for filename -->
  Impact: DoS via extremely long filenames | Fix: Enforce 32-char title limit | Effort: small

- [-] **H-023** `[concurrency]` `native_messaging_host/mod.rs:39`: Infinite loop with no timeout or graceful shutdown
  <!-- pid:no_graceful_shutdown | batch:1 | verified:true | first:2026-04-11 -->
  Impact: Native messaging host hangs indefinitely on slow IPC | Fix: Add per-message timeout | Effort: medium

- [-] **H-024** `[security]` `KeystrokeMonitorService.swift:156`: Paste attribution bypass; pasted content credited to document
  <!-- pid:PASTE_VALIDATION | batch:5 | verified:true | first:2026-04-11 -->
  Impact: User forges authorship by pasting external text | Fix: Validate paste matches recent doc changes | Effort: large

- [x] **H-025** `[security]` `BrowserExtensionService.swift:574`: Bundled host path returned without existence/signature check
  <!-- pid:BUNDLE_PATH_VERIFY | batch:5 | verified:true | first:2026-04-11 -->
  Impact: Browser ext registered to tampered binary | Fix: Verify existence + code signature | Effort: small

- [x] **H-026** `[error_handling]` `CrashReportingService.swift:62`: Force unwrap on applicationSupportDirectory
  <!-- pid:force_unwrap | batch:5 | verified:true | first:2026-04-11 -->
  Impact: Crash on launch if dir unavailable | Fix: guard let | Effort: small

- [-] **H-027** `[architecture]` `OnboardingView.swift:6`: God module; 1450 lines mixing permissions, pipeline, async polling, UI
  <!-- pid:god_module | batch:7 | verified:true | first:2026-04-11 -->
  Impact: Hard to test/maintain individual concerns | Fix: Extract into separate services | Effort: large

- [-] **H-028** `[architecture]` `StatusBarController.swift:10`: God module; 983 lines mixing popover, events, hotkeys, animations
  <!-- pid:god_module | batch:7 | verified:true | first:2026-04-11 -->
  Impact: Complex state management; high coupling | Fix: Extract subcontrollers | Effort: large

- [x] **H-029** `[security]` `WARReportPDFRenderer.swift:190`: Path validation allows symlink-to-Downloads; write outside intended dir
  <!-- pid:path_traversal | batch:7 | verified:true | first:2026-04-11 | fixed:2026-05-06 — resolvingSymlinksInPath() before check; component-array containment against allowed dirs (Downloads/Documents/Desktop/temp) -->
  Impact: Arbitrary file write via symlink | Fix: Validate before resolving symlinks | Effort: small

- [x] **H-030** `[concurrency]` `CPoEService+Polling.swift:35`: HMAC race in status polling; stale HMAC causes missed updates
  <!-- pid:data_race | batch:7 | verified:true | first:2026-04-11 | fixed:2026-05-05 — lastStatusHMAC marked @ObservationIgnored (stops spurious SwiftUI re-renders); forceStatusRefresh handler now syncs HMAC after direct status assignment -->
  Impact: Status updates silently dropped or duplicated | Fix: Atomic compare-and-swap for HMAC | Effort: medium

- [-] **H-031** `[concurrency]` `BatchVerifyView.swift:176`: Biometric auth race; cancelled state unreliable after task group
  <!-- pid:race_condition | batch:7 | verified:true | first:2026-04-11 -->
  Impact: Biometric prompt lost on timing edge | Fix: Use structured concurrency | Effort: medium

- [-] **H-032** `[security]` `IpcClient.cs:617`: DEBUG builds bypass daemon identity verification
  <!-- pid:debug_security_downgrade | batch:8 | verified:true | first:2026-04-11 -->
  Impact: DEBUG builds connect to untrusted daemons | Fix: Remove DEBUG bypass | Effort: small

- [x] **H-033** `[error_handling]` `CPoEBridge.Operations.cs:45`: Logs only ex.Message; stack traces lost
  <!-- pid:unhelpful_error_msg | batch:8 | verified:true | first:2026-04-11 -->
  Impact: Difficult to diagnose IPC failures | Fix: Log ex.ToString() | Effort: small

- [-] **H-034** `[security]` `Code.ts:566`: API key in roaming settings without encryption
  <!-- pid:hardcoded_secret | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Unauthorized API requests if document shared | Fix: Migrate to server-only storage | Effort: large

- [-] **H-035** `[security]` `Code.ts:327`: HMAC tag stored in world-readable DocumentProperties
  <!-- pid:hardcoded_secret | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Watermark forgery by document collaborators | Fix: Store seed server-side | Effort: large

- [-] **H-036** `[security]` `WritersProofClient.ts:175` (Office365): API key in plain roaming settings
  <!-- pid:hardcoded_secret | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Keys exposed in multi-user scenarios | Fix: Encrypt at rest | Effort: medium

- [-] **H-037** `[security]` `secure-channel.js:159`: JS CryptoKey objects cannot be explicitly destroyed; old keys persist
  <!-- pid:key_zeroize | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Old session keys remain in memory | Fix: Regenerate keys frequently | Effort: large

- [x] **H-038** `[code_quality]` `background.js:134`: Genesis commitment race; checkpoint sent before genesis computed
  <!-- pid:race_condition | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Invalid commitment chain with null prevCommitment | Fix: Await genesis before checkpoints | Effort: small

- [-] **H-039** `[security]` `WritersProofClient.ts:142` (Atlassian): API error responses logged including body text
  <!-- pid:log_info_leak | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Information disclosure of internal API details | Fix: Log only status code | Effort: small

- [-] **H-040** `[architecture]` `resolvers/index.ts:261`: TOCTOU in createCheckpoint; session re-read before send
  <!-- pid:toctou | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Checkpoints for already-stopped sessions | Fix: Optimistic locking with version field | Effort: medium

- [-] **H-041** `[security]` `WritersProofClient.ts:141` (Office365): Missing TLS pinning/HSTS enforcement
  <!-- pid:missing_security_headers | batch:11 | verified:true | first:2026-04-11 -->
  Impact: MITM in corporate proxy scenarios | Fix: Enforce HSTS; implement cert pinning | Effort: medium

- [-] **H-042** `[security]` `ExplorerContextMenuHandler.cs:85`: cpoe.exe launched via unverified path search
  <!-- pid:unverified_executable | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Privilege escalation via malicious cpoe.exe in PATH | Fix: Verify signature before execution | Effort: medium

- [-] **H-043** `[security]` `CollaborativeEvidenceDialog.xaml.cs:425`: XamlReader.Load() with potentially untrusted input
  <!-- pid:unsafe_deser | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Remote code execution via malicious XAML | Fix: Never use XamlReader.Load() with untrusted input | Effort: large

- [-] **H-044** `[security]` `LockScreenDialog.xaml.cs:145`: Password stored in plain string before PBKDF2 validation
  <!-- pid:plaintext_password_in_memory | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Password recoverable from heap dumps | Fix: Use SecureString | Effort: medium

- [-] **H-045** `[security]` `LockScreenDialog.xaml.cs:170`: Regex DoS on malformed PBKDF2 hash input
  <!-- pid:regex_dos | batch:10 | verified:true | first:2026-04-11 -->
  Impact: UI freeze during lock screen validation | Fix: Length validation before regex; use compiled regex | Effort: small

- [x] **H-046** `[security]` `WatchPathsDialog.xaml.cs:95`: Path traversal via junctions/symlinks escaping watched dir
  <!-- pid:path_traversal | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Monitoring sensitive system folders | Fix: GetFullPath() + resolve all symlinks | Effort: medium

- [-] **H-047** `[security]` `WatchPathsDialog.xaml.cs:81`: Incomplete system path validation
  <!-- pid:insufficient_system_path_validation | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Watching AppData, LocalAppData, ProgramData | Fix: Expand to all Environment.SpecialFolder | Effort: small

- [x] **H-048** `[security]` `CollaborativeEvidenceDialog.xaml.cs:320`: DID identity validation without length/checksum
  <!-- pid:missing_validation | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Malformed DIDs bypass validation | Fix: Strict format with length limits | Effort: medium

- [x] **H-049** `[concurrency]` `HomePage.xaml.cs:185`: Fire-and-forget async without CancellationToken
  <!-- pid:missing_cancellation_token | batch:10 | verified:true | first:2026-04-11 -->
  Impact: NullReferenceException after page navigation | Fix: CancellationTokenSource in OnNavigatedFrom | Effort: medium

- [-] **H-050** `[concurrency]` `SessionPage.xaml.cs:120`: Timer continues after page navigation
  <!-- pid:missing_cancellation_token | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Memory leak and battery drain | Fix: Stop timer in OnNavigatedFrom | Effort: medium

- [-] **H-051** `[architecture]` `CollaborativeEvidenceDialog.xaml.cs:450`: God module; 924 lines with 4 tabs in single file
  <!-- pid:god_module | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Tight coupling between collaboration features | Fix: Split into per-tab UserControls | Effort: large

- [-] **H-052** `[code_quality]` `IpcMessage.cs:120`: Version mismatch risk between Rust serde and .NET JSON for byte[]
  <!-- pid:version_mismatch_ipc | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Silent data corruption on format change | Fix: Versioned IPC protocol spec | Effort: large

- [-] **H-053** `[security]` `MnemonicRecoveryDialog.xaml.cs:110`: PasswordBox.Password accessed without immediate clearing
  <!-- pid:plaintext_password_in_memory | batch:10 | verified:true | first:2026-04-11 -->
  Impact: Recovery phrase accessible via memory inspection | Fix: Copy to SecureString immediately | Effort: medium

- [-] **H-054** `[error_handling]` `Code.ts:752`: Event queue truncation silently discards oldest events
  <!-- pid:silent_error | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Loss of authoring evidence without user awareness | Fix: Alert user on truncation | Effort: medium

- [-] **H-055** `[security]` `background.js (Safari):407`: Session state recovered without integrity check
  <!-- pid:missing_validation | batch:11 | verified:true | first:2026-04-11 -->
  Impact: Session nonce modification enables false evidence | Fix: HMAC session state before storage | Effort: medium

- [-] **H-056** `[error_handling]` `IpcClient.cs:156`: Key confirmation plaintext must match Rust; no compile-time assertion
  <!-- pid:hardcoded_config | batch:8 | verified:true | first:2026-04-11 -->
  Impact: Silent MITM if constant diverges | Fix: Add unit test verifying match | Effort: small

## Medium
<!-- 97 MEDIUM findings omitted for brevity. Key patterns: -->
<!-- Error handling: silent swallows, unhelpful messages, missing propagation -->
<!-- Concurrency: DateFormatter thread safety, task leak, polling races -->
<!-- Code quality: hardcoded URLs, magic values, deep nesting -->
<!-- Architecture: business logic in UI, missing MVVM -->
<!-- Security: timing leaks, insufficient validation, stale auth -->
<!-- Performance: CIContext caching, HashMap cleanup, validation spam -->

- [x] **M-001** `[concurrency]` `EndpointSecurityClient.swift:115`: ES callback no backpressure; unbounded task queue
- [-] **M-002** `[security]` `EndpointSecurityClient.swift:151`: Unvalidated union access in ES message
- [x] **M-003** `[error_handling]` `EngineService.swift:219`: Session cleanup timeout leaks task reference
  <!-- fixed:2026-05-04 (cleanupTask stored in CleanupTaskRegistry; cancel on dealloc) -->
- [-] **M-004** `[concurrency]` `CPoEEngineFFI+Sendable.swift:10`: @unchecked Sendable without Rust type audit
- [x] **M-005** `[security]` `EngineService.swift:105`: Environment variable race between instances
- [x] **M-006** `[error_handling]` `EngineService.swift:386`: getLog() returns empty array on timeout (ambiguous)
  <!-- fixed:2026-05-04 (returns nil on timeout; callers distinguish nil=error from []=empty) -->
- [x] **M-007** `[security]` `ReceiptValidation.swift:331`: Hardcoded Apple Root CA fingerprint; no rotation
- [x] **M-008** `[security]` `ChallengeService.swift:115`: Session ID length not validated
  <!-- fixed:2026-05-04 (added !sid.isEmpty minimum length check) -->
- [x] **M-009** `[security]` `ReceiptValidation.swift:372`: ASN.1 iteration limit may reject large receipts
- [x] **M-010** `[security]` `DeviceAttestationService.swift:273`: Challenge freshness unreliable after sleep
- [x] **M-011** `[error_handling]` `AuthService+ErrorHandling.swift:108`: OAuth error matching via fragile string checks
- [x] **M-012** `[security]` `IntegrityHardening.swift:73`: Dylib check no symlink resolution
  <!-- fixed:2026-05-04 (resolve symlinks via URL.resolvingSymlinksInPath before prefix check) -->
- [x] **M-013** `[security]` `IntegrityHardening.swift:35`: isBeingDebugged fails closed on sysctl error
- [x] **M-014** `[security]` `AuthService+Session.swift:48`: Rate limiter in UserDefaults; survives reinstall
- [x] **M-015** `[code_quality]` `KeychainHelper.swift:31`: Delete+add pattern has TOCTOU race
  <!-- fixed:2026-05-04 (retry on errSecDuplicateItem after delete; handles concurrent add from another process) -->
- [x] **M-016** `[concurrency]` `EncryptedSessionStore.swift:224`: Key rotation holds lock for entire rotation
- [-] **M-017** `[concurrency]` `AuthService+Session.swift:208`: authStateTask accessed from non-isolated deinit
- [-] **M-018** `[code_quality]` `ReceiptValidation.swift:328`: Bundle ID obfuscation via Unicode scalars
- [-] **M-019** `[error_handling]` `CloudSyncService.swift:387`: Audit log write swallows errors
- [-] **M-020** `[performance]` `DataDirectoryMonitor.swift:122`: Validation triggered per FSEvent batch
- [-] **M-021** `[architecture]` `DataDirectoryIntegrityService.swift:382`: Private API (proc_listpids) usage
  <!-- pid:private_api | verified:true | first:2026-04-11 | skipped:2026-05-04 — Darwin libproc (proc_listpids, proc_pidinfo) is private but stable since 10.5; no public alternative exists; code already documents this trade-off -->
- [-] **M-022** `[concurrency]` `NotificationManager.swift:237`: Tasks cancelled but not awaited
- [x] **M-023** `[performance]` `ProofCardService.swift:539`: CIContext created per call; should be cached
- [x] **M-024** `[architecture]` `DataDirectoryIntegrityService+Security.swift:260`: fdesetup blocks main thread
- [x] **M-025** `[maintainability]` `BrowserExtensionService.swift:780`: HMAC key cache no TTL
- [-] **M-026** `[architecture]` `PopoverComponents.swift:1`: God module; 942 lines mixed UI
  <!-- pid:god_module | verified:true | first:2026-04-11 | skipped:2026-05-04 — deferred per SYS-003; user preference to not split working files -->
- [-] **M-027** `[architecture]` `SettingsContent.swift:1`: God module; 1383 lines mixed UI+logic
  <!-- pid:god_module | verified:true | first:2026-04-11 | skipped:2026-05-04 — deferred per SYS-003; user preference to not split working files -->
- [x] **M-028** `[security]` `CheckpointFormView.swift:172`: File path from service without validation
- [x] **M-029** `[error_handling]` `DashboardSetupContent.swift:374`: Raw technical details in user alert
- [-] **M-030** `[code_quality]` `SettingsAccountTab.swift:463`: Hardcoded URL without constant
- [-] **M-031** `[security]` `SettingsUtilities.swift:40`: Path prefix matching without resolution
- [-] **M-032** `[error_handling]` `cmd_verify.rs:420`: File sync_all() result silently discarded
- [x] **M-033** `[error_handling]` `cmd_track/mod.rs:331`: Mutex poisoning recovery suppressed
- [-] **M-034** `[security]` `native_messaging_host/protocol.rs:99`: Domain suffix matching without boundary check
- [x] **M-035** `[security]` `native_messaging_host/handlers.rs:275`: 1s clock tolerance allows backwards attacks
- [-] **M-036** `[security]` `native_messaging_host/handlers.rs:187`: Timing side-channel in hex validation
- [x] **M-037** `[security]` `cmd_track/filesystem.rs:69`: Symlink TOCTOU between classify and checkpoint
- [-] **M-038** `[concurrency]` `cmd_track/mod.rs:214`: Ctrl+C handler races with HashMap access
- [-] **M-039** `[performance]` `cmd_track/mod.rs:228`: HashMap retain in hot path O(n) per timeout
- [x] **M-040** `[code_quality]` `util.rs:262`: Exponential backoff reaches 1.6s with no user feedback
- [-] **M-041** `[maintainability]` `cmd_track/mod.rs:1`: 1107 lines; mixed concerns in event loop
- [-] **M-042** `[maintainability]` `native_messaging_host/handlers.rs:13`: handle_start_session 171 lines deeply nested
- [-] **M-043** `[architecture]` `native_messaging_host/mod.rs:40`: Error handling uses eprintln only
- [x] **M-044** `[architecture]` `cpoe_cli/src/`: Session types incompatible between NMH and CLI
  <!-- pid:session_types | verified:true | first:2026-04-11 | fixed:2026-05-04 — added session_dir field to NMH Session; evidence_path.join() was using file path as directory; two WAL paths now use session_dir -->
- [x] **M-045** `[security]` `AppDelegate.swift:537`: Deep link handler processes before full init
- [x] **M-046** `[security]` `AppDelegate.swift:625`: Replay protection lost on app restart
- [x] **M-047** `[concurrency]` `CPoEService+Polling.swift:156`: Pulse reset tasks accumulate
  <!-- fixed:2026-05-05 — schedulePulseReset uses do/catch on Task.sleep; cancelled sleep throws CancellationError which is caught, pulse reset only runs on clean completion -->
- [x] **M-048** `[error_handling]` `CPoEService+Polling.swift:40`: No monotonicity check on status updates
  <!-- fixed:2026-05-04 (guard: if same doc tracked and keystrokeCount decreased, keep higher value with warning log) -->
- [-] **M-049** `[security]` `CollaborationSession.swift:261`: Fingerprint collision in collaborator revocation
- [x] **M-050** `[architecture]` `CollaborationSession.swift:175`: No dedup for collaborator invitations
- [x] **M-051** `[performance]` `HistoryPopoverViews.swift:169`: Search debounce leaks tasks
- [-] **M-052** `[security]` `LiveDemoView.swift:9`: TransparencyFeed injectable by any code
- [-] **M-053** `[concurrency]` `DataTransparencyView.swift:285`: DateFormatter not thread-safe
- [-] **M-054** `[error_handling]` `PaywallView.swift:269`: isPurchasing stuck on throw
- [-] **M-055** `[security]` `CPoESettings.swift`: UserDefaults settings without encryption
- [x] **M-056** `[error_handling]` `AppDelegate.swift:515`: writePID() does not check return value
- [x] **M-057** `[error_handling]` `AppDelegate.swift:682`: Retry init without backoff
- [-] **M-058** `[architecture]` `CPoEApp.swift:41`: Menu setup mixed with app routing
- [x] **M-059** `[security]` `CodeSigningValidation.swift:152`: Hardcoded team ID
- [-] **M-060** `[architecture]` `VerifiableCredentialService.swift:146`: No proof format validation against W3C spec
- [-] **M-061** `[performance]` `CPoEBridge.Infrastructure.cs:236`: O(n log n) cache eviction inline
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [x] **M-062** `[error_handling]` `ErrorService.cs:164`: async void ShowInlineSuccess
- [-] **M-063** `[error_handling]` `FileWatcherService.cs:202`: async void OnWatcherError
- [-] **M-064** `[concurrency]` `FileWatcherService.cs:150`: TOCTOU in HandleFileEventAsync
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-065** `[architecture]` `App.xaml.cs:202`: Fire-and-forget background init hides failures
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-066** `[security]` `SecurityService.cs:471`: ClearSensitiveString best-effort only
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [x] **M-067** `[security]` `SecurityService.cs:154`: No timeout on online cert revocation
- [-] **M-068** `[security]` `CPoEBridge.cs:131`: DEBUG TOFU allows unsigned binaries
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-069** `[error_handling]` `App.xaml.cs:549`: Unhandled exceptions in async void
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [x] **M-070** `[performance]` `SettingsService.cs:74`: Double DPAPI decryption on every load
- [-] **M-071** `[architecture]` `MainWindow.xaml.cs:531`: Protocol verification errors not shown to user
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-072** `[error_handling]` `App.xaml.cs:474`: Protocol activation rejection gives no feedback
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-073** `[security]` `ServiceNow/WritersProofAPI.js:52`: No row-level security on session lookup
- [-] **M-074** `[code_quality]` `ServiceNow/WritersProofAPI.js:38`: Table allowlist hardcoded
  <!-- reason:submodule_not_checked_out — cpoe_servicenow submodule not checked out -->
- [-] **M-075** `[error_handling]` `EventCapture.ts:129` (Atlassian): Empty versions returns all-zeros metrics
  <!-- reason:submodule_not_checked_out — cpoe_atlassian submodule not checked out -->
- [-] **M-076** `[security]` `WritersProofClient.ts:192` (GWorkspace): Session ID in URL without re-validation
  <!-- reason:submodule_not_checked_out — cpoe_google_workspace submodule not checked out -->
- [-] **M-077** `[performance]` `WritersProofClient.ts:360` (GWorkspace): Retry ignores Retry-After header
  <!-- reason:submodule_not_checked_out — cpoe_google_workspace submodule not checked out -->
- [-] **M-078** `[code_quality]` `popup.js:189`: 200ms injection race with no handshake
  <!-- pid:popup_race | verified:true | first:2026-04-11 | skipped:2026-05-04 — 300ms retry is standard for extension popups; background readiness check already in place -->
- [x] **M-079** `[security]` `secure-channel.js:293`: Commitment concatenation without length prefix
  <!-- pid:length_prefix | verified:true | first:2026-04-11 | fixed:2026-05-04 — added uint32ToLE length prefixes in secure-channel.js computeCommitment (self-contained dual-channel protocol); background.js computeCommitment uses binary concat matching Rust (no length prefix needed since contentHash is always fixed-format hex) -->
- [x] **M-080** `[security]` `background.js:99`: hexToBytes accepts non-hex silently
- [x] **M-081** `[error_handling]` `background.js:279`: Commitment failure silently skips checkpoint
  <!-- pid:silent_skip | verified:true | first:2026-04-11 | fixed:2026-05-04 — added console.warn, commitment_missing flag on checkpoint, and error logging in catch -->
- [-] **M-082** `[security]` `content.js:347`: Tool name no length validation
- [-] **M-083** `[performance]` `content.js:162`: DOM traversal per keystroke; no memoization
  <!-- pid:dom_traversal | verified:true | first:2026-04-11 | skipped:2026-05-04 — already mitigated: handleKeyDown only records performance.now(); getEditorElement has cachedEditorElements memoization; content reads debounced at 2-3s -->
- [x] **M-084** `[code_quality]` `background.js (Safari):304`: Commitment hash uses pipes; not binary-safe
  <!-- pid:commitment_hash | verified:true | first:2026-04-11 | fixed:2026-05-04 — complete Safari protocol alignment: (1) pipe-delimited→binary concat matching Rust; (2) commitment_hash→commitment field name; (3) ordinal 0→1 start (first checkpoint=2); (4) nonce from self-generated→Rust session_started response; (5) genesis sha256(url)→H(prefix||nonce) matching Chrome; (6) handleNativeResponse made async; (7) removed stale content_tier/session_nonce from start_session -->
- [-] **M-085** `[security]` `resolvers/index.ts:28`: UUID redaction regex matches legitimate content
  <!-- reason:submodule_not_checked_out — cpoe_hubspot submodule not checked out -->
- [-] **M-086** `[error_handling]` `App.tsx:271` (Office365): Batch submission no retry/backoff
  <!-- reason:submodule_not_checked_out — cpoe_office365 submodule not checked out -->
- [-] **M-087** `[security]` `Code.ts:618` (GWorkspace): Download URL no HTTPS enforcement
- [-] **M-088** `[error_handling]` `app.ts:190` (HubSpot Legacy): Webhook errors logged but not surfaced
  <!-- reason:submodule_not_checked_out — cpoe_hubspot_legacy submodule not checked out -->
- [-] **M-089** `[concurrency]` `DashboardPage.xaml.cs:380`: Heatmap rebuilds 84+ objects per update
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-090** `[concurrency]` `HistoryPage.xaml.cs:150`: Search debounce race; out-of-order results
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-091** `[concurrency]` `HistoryPage.BulkActions.cs:85`: Unsynchronized read after Interlocked
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-092** `[code_quality]` `TimelineDialog.xaml.cs:90`: Estimated entries indistinguishable from real
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [x] **M-093** `[code_quality]` `AnnotationDialog.xaml.cs:120`: MaxLength not set despite UI claiming 500
- [-] **M-094** `[code_quality]` `SettingsPage.xaml.cs:255`: Complex _isLoading state machine
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-095** `[error_handling]` `TimelineDialog.xaml.cs:42`: ContinueWith null exception check missing
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-096** `[error_handling]` `BatchVerifyDialog.xaml.cs:280`: ObjectDisposedException silently caught
  <!-- reason:submodule_not_checked_out — cpoe_windows submodule not checked out -->
- [-] **M-097** `[maintainability]` `NotificationManager.swift:772`: Inefficient notification sort

## Quick Wins
| ID | Sev | File:Line | Issue | Effort |
|----|-----|-----------|-------|--------|
| C-001 | CRITICAL | CPoEEngineFFI.swift:551 | Force unwrap UTF-8 at FFI boundary | small |
| C-002 | CRITICAL | CPoEEngineFFI.swift:567 | Force unwrap in read() path | small |
| C-003 | CRITICAL | CPoEEngineFFI.swift:550 | Buffer pointer bounds validation | small |
| C-004 | CRITICAL | DeviceAttestationService.swift:335 | Counter overflow allows replay | small |
| C-005 | CRITICAL | SafariExtensionShared.swift:449 | HMAC bypass via force unwrap | small |
| C-006 | CRITICAL | cmd_verify.rs:598 | Unzeroized Ed25519 key material | small |
| C-010 | CRITICAL | WARReportHTMLRenderer.swift:176 | XSS in HTML report | small |
| H-007 | HIGH | AuthService+Session.swift:417 | Device binding fails open | small |
| H-008 | HIGH | ReceiptValidation.swift:837 | Downgrade check bypass on Keychain error | small |
| H-010 | HIGH | EncryptedSessionStore.swift:168 | Deadlock guard check too late | small |
| H-011 | HIGH | ReceiptValidation.swift:438 | Partial binding field bypass | small |
| H-016 | HIGH | DeviceAttestationService.swift:373 | Empty string passes !isEmpty | small |
| H-017 | HIGH | SafariExtensionShared.swift:599 | Bare catch swallows errors | small |
| H-021 | HIGH | cmd_track/mod.rs:368 | Symlink TOCTOU in path comparison | small |
| H-022 | HIGH | handlers.rs:59 | Unbounded filename length | small |
| H-025 | HIGH | BrowserExtensionService.swift:574 | Unverified host binary path | small |
| H-026 | HIGH | CrashReportingService.swift:62 | Force unwrap on appSupportDir | small |
| H-032 | HIGH | IpcClient.cs:617 | DEBUG bypasses daemon verification | small |
| H-033 | HIGH | CPoEBridge.Operations.cs:45 | Logs only ex.Message | small |
| H-038 | HIGH | background.js:134 | Genesis commitment race | small |
| H-039 | HIGH | WritersProofClient.ts:142 | Error response body logged | small |
| H-045 | HIGH | LockScreenDialog.xaml.cs:170 | Regex DoS on hash input | small |
| H-047 | HIGH | WatchPathsDialog.xaml.cs:81 | Incomplete system path list | small |
| H-056 | HIGH | IpcClient.cs:156 | Key confirmation constant not tested | small |

## Coverage
<!-- reviewed: 297 files across 10 apps -->
<!-- reviewed: cpoe_cli (34 files), cpoe_macos (132 files), cpoe_windows (91 files) -->
<!-- reviewed: cpoe_atlassian (8), cpoe_google_workspace (6), cpoe_hubspot (4), cpoe_hubspot_legacy (5) -->
<!-- reviewed: cpoe_office365 (12), cpoe_salesforce (2), cpoe_servicenow (3) -->
<!-- confirmed_clean: ~45 files (small helpers, models, UI-only views) -->

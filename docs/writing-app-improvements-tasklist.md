# Writing App Support Improvements — Task List v3

## Architecture Review

### What the codebase already does well
- **Auto-discovery** (`app_discovery.rs`): Probes unknown apps at runtime via Electron detection, group containers, iCloud, SQLite, AX accessibility, Info.plist UTIs. Caches in-session, persists to `user_apps.json`.
- **Generic title parsing** (`types.rs:2052`): Already handles em-dashes, pipes, and hyphens. Apps like Highland 2 and Mellel already parse correctly.
- **Format-based enrichment** (`helpers.rs:1882-1900`): `build_event()` enriches context_note with word count, track changes, and FDX fingerprint — keyed on file extension, not app. Adding a format here benefits every app that uses it.
- **Export detection** (`helpers.rs:2736`): `detect_export_event()` is app-agnostic — correlates any new file with export extension within 30 seconds of session focus.

### What's actually broken (in priority order)
1. **Export attestation is gated on adapters** (`sentinel_es.rs:64`): Only 5 of 109 apps get export evidence. The detection logic is app-agnostic but the calling code isn't.
2. **Print-to-PDF is invisible**: macOS system print processes aren't recognized.
3. **Version-specific bundle IDs** require manual entries per app version.
4. **ZIP scanning is copy-pasted 3x** for FDX alone (lines 2429-2450, 2550-2570, 2888-2908), with inconsistent constant names (`LOCAL_HEADER_SIG` vs `ZIP_SIG`).
5. **Format intelligence covers only**: word count (5 formats), revision detection (2 formats), structural fingerprint (1 format).
6. **~20 writing format extensions** are missing from `DOC_EXTENSIONS`.

---

## Phase 0: Foundation

### T-000: Extract shared ZIP utilities, eliminate FDX triplication

**Problem**: Three FDX functions (`extract_word_count_fdx`, `has_fdx_revisions`, `parse_fdx_scene_fingerprint`) each independently:
- Open the file and peek at 4 magic bytes
- Scan ZIP entries in a loop (50-iteration cap) to find one ending in `.fdx`
- Fall back to plain XML if not ZIP
- Read the content as a String

This is ~60 lines duplicated 3 times. Additionally, `read_zip_entry_bytes()` (line 2786) already handles ZIP parsing with better limits (500 entries, 100 MiB file cap, 16 MiB decompression cap, flate2 support), but the FDX functions don't use it.

**What**: Create two utilities:

```rust
/// Constant for ZIP local file header signature.
const ZIP_LOCAL_HEADER_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Find the first ZIP entry whose name ends with `suffix`.
/// Returns the entry name, or None if the file is not a ZIP or no entry matches.
fn find_zip_entry_by_suffix(path: &Path, suffix: &str) -> Option<String>

/// Read XML from a file that may be ZIP-wrapped or plain text.
/// If ZIP: finds an entry matching `inner_suffix`, extracts via read_zip_entry_bytes().
/// If not ZIP: reads the file directly (capped at MAX_HASH_FILE_SIZE).
fn read_xml_content(path: &Path, inner_suffix: &str) -> Option<String>
```

Also rename `read_docx_entry()` → `read_zip_entry_as_str()` (it's just `read_zip_entry_bytes` + UTF-8 conversion; the name misleadingly ties it to docx).

Refactor all three FDX functions to use `read_xml_content(path, ".fdx")`. Refactor `extract_word_count_docx` and `has_track_changes` (docx branch) to use `read_zip_entry_as_str()`.

Standardize the ZIP signature constant: replace all 7 occurrences of inline `[0x50, 0x4B, 0x03, 0x04]` (except in test helper `build_minimal_docx`) with `ZIP_LOCAL_HEADER_SIG`.

**Completion criteria**:
- Zero inline ZIP magic byte arrays outside the constant definition and test helper
- `parse_fdx_scene_fingerprint()`, `extract_word_count_fdx()`, `has_fdx_revisions()` each reduced to <15 lines using `read_xml_content()`
- `read_docx_entry` renamed to `read_zip_entry_as_str`; 2 callers updated
- All existing FDX and DOCX tests pass unchanged
- Net reduction of ~120 lines
- Zero clippy warnings

**Files**: `crates/cpoe/src/sentinel/helpers.rs`

---

### T-001: Decouple export attestation from adapter_for_bundle()

**Problem**: In `ffi/sentinel_es.rs:56-90`, the export detection loop has TWO gates that block seamless operation:

1. **Line 58**: `segment_counts.is_empty()` skips non-bundle sessions — so Pages, Word, Obsidian, Bear, Ulysses (file-based, not bundle-based) are excluded entirely.
2. **Line 64**: `adapter_for_bundle()` skips apps without adapters — so 104 of 109 registered apps and all auto-discovered apps are excluded.

```rust
for session in sentinel.sessions() {
    // Gate 1: only bundle sessions (Scrivener, Vellum packages)
    if session.segment_counts.is_empty() && session.scrivener_project_map.is_none() {
        continue;
    }
    // Gate 2: only apps with adapters
    if let Some(adapter) = adapter_for_bundle(session_bid) {
        if !adapter.is_compile_process(process_name) { continue; }
        // ... detect_export_event() ...
    }
}
```

Result: File > Export to PDF/EPUB/DOCX/TXT from Pages, Word, Obsidian, Bear, iA Writer, Highland, Ulysses, and every other non-bundle app produces zero attestation. The user exports a manuscript and WritersProof doesn't notice.

**What**: Restructure the loop into two tiers:

1. **High-confidence path** (existing): If session is a bundle AND adapter exists AND `is_compile_process` matches, produce attestation with `correlation_confidence: "high"`.
2. **Standard path** (new, the "just works" path): For ALL sessions (bundle or not), if no adapter match was found, still call `detect_export_event()` for any session that was focused within the 30-second window. The existing time-window + extension + keystroke-count guards in `detect_export_event()` are sufficient. Remove the `segment_counts` gate entirely from the standard path.

The standard path is what makes export attestation seamless — any app, any format, zero configuration. The user exports from Pages, Obsidian, or a brand-new app we've never seen, and the attestation just appears.

**Completion criteria**:
- Session in Pages (file-based, no segments) that exports a PDF gets `ManuscriptExportAttestation`
- Session in Obsidian (no adapter) that exports to HTML gets `ManuscriptExportAttestation`
- Session with adapter still gets the additional process-name verification (no regression)
- Auto-discovered app that exports gets attestation without any adapter
- Test: mock file-based session (no segments), file write with `.pdf` extension → attestation
- Test: mock session without adapter, file write with `.epub` extension → attestation
- Test: mock bundle session with adapter, compile process match → high-confidence attestation

**Files**: `crates/cpoe/src/ffi/sentinel_es.rs`

---

### ~~T-002: System-level Print-to-PDF detection~~ — ELIMINATED

**Verified 2026-06-18**: macOS "Save as PDF" is an **in-process operation**. The originating app (not a system print process) renders the PDF via Core Graphics and writes it to disk. Confirmed by printing from Pages — the file's `com.apple.quarantine` xattr shows `Pages` as the creating process. No `PrintUITool`, `printtool`, `pstopdf`, or CUPS filters are involved in the file write.

**Process names discovered during testing** (for reference only — none write the PDF):
| Process | Signing ID | Role |
|---------|-----------|------|
| `PrintUITool` | `com.apple.printuitool` | Print dialog UI (no file I/O) |
| `printtool` | `com.apple.print.daemon.printtool` | Print daemon agent (no file I/O) |
| `com.apple.PrintKit.PrinterTool` | `com.apple.PrintKit.PrinterTool` | XPC printer discovery service |
| `riousbprint` | — | USB printer discovery |

**Resolution**: T-001 (decouple export attestation) already covers Print-to-PDF. Once export detection is ungated from `adapter_for_bundle()`, any app that writes a `.pdf` while focused gets `ManuscriptExportAttestation` automatically. No separate task needed.

---

### T-003: Prefix-based bundle ID matching

**Problem**: Final Draft versions 10–13 each need separate registry entries AND separate `adapter_for_bundle()` routes. Final Draft 14 will need another. Same issue for any versioned app.

**What**:

1. In `adapter_for_bundle()`, after the exact-match block, add prefix fallback:
```rust
// Prefix-based fallback for versioned apps
if bundle_id.to_ascii_lowercase().starts_with("com.finaldraft.mac.") {
    return Some(Box::new(FinalDraftAdapter));
}
```

2. In `lookup()`, after the exact-match search, add prefix fallback: if no exact match, try matching the longest registered prefix (e.g., `com.finaldraft.mac.fd99` falls back to the `com.finaldraft.mac.fd13` entry's metadata).

3. Remove the individual FD 12 and FD 13 entries we just added (they're now redundant — the prefix handles them). Keep FD 10 and FD 11 as the two canonical entries (different enough to warrant distinct display names).

**Completion criteria**:
- `adapter_for_bundle("com.finaldraft.mac.fd99")` returns `Some(FinalDraftAdapter)`
- `lookup("com.finaldraft.mac.fd14")` returns metadata (falls back to nearest match)
- Exact matches still take priority
- Test: unknown FD version gets adapter

**Files**: `crates/cpoe/src/sentinel/app_registry.rs`

---

## Phase 1: Format Intelligence — Word Count

All format functions are dispatched by file extension in `extract_word_count()` (line ~2277), which is called from `build_event()` (line 1885). Adding a format here benefits every app that saves in that format — present, future, registered, and auto-discovered.

The shared utilities from T-000 (`read_xml_content`, `read_zip_entry_as_str`, `strip_xml_tags`) eliminate duplication across all ZIP-based formats.

### T-004: ODT word count

**What**: `"odt" => extract_word_count_odt(path)`. ODT is ZIP with `content.xml`. Use `read_zip_entry_as_str(path, "content.xml")` (from T-000) + existing `strip_xml_tags()`.

**Completion criteria**: Test with minimal ODT ZIP. Returns `None` for corrupt. **Files**: `helpers.rs`

---

### T-005: Fountain word count

**What**: `"fountain" => extract_word_count_fountain(path)`. Plain text. Strip: title page (key-value lines before first blank line), boneyard (`/* ... */`), notes (`[[ ... ]]`), synopsis (`=`), section headers (`#`), centering markers. Count remaining words.

**Completion criteria**: Test excluding title page, notes, boneyard. **Files**: `helpers.rs`

---

### T-006: LaTeX word count

**What**: `"tex" | "latex" => extract_word_count_tex(path)`. Strip preamble (before `\begin{document}`), comments (`%`), math (`$...$`, `\[...\]`), commands. Keep text from text-bearing commands (`\textbf{kept}`).

**Completion criteria**: Test with preamble, math, comments, body. **Files**: `helpers.rs`

---

### T-007: OPML word count

**What**: `"opml" => extract_word_count_opml(path)`. XML. Extract `text` attributes from `<outline>` elements via `strip_xml_tags()` after isolating `text="..."` values.

**Completion criteria**: Test with nested outlines. **Files**: `helpers.rs`

---

### T-008: Org-mode word count

**What**: `"org" => extract_word_count_org(path)`. Plain text. Strip `#+` metadata, property drawers (`:PROPERTIES:`...`:END:`), comment lines (`# `), timestamps, link syntax (`[[url][text]]` → keep text).

**Completion criteria**: Test with headers, properties, links, prose. **Files**: `helpers.rs`

---

### T-009: reStructuredText word count

**What**: `"rst" => extract_word_count_rst(path)`. Plain text. Strip directive lines (`.. directive::`), field lists, comment blocks, raw blocks.

**Completion criteria**: Test with directives, sections, prose. **Files**: `helpers.rs`

---

### T-010: AsciiDoc word count

**What**: `"adoc" | "asciidoc" => extract_word_count_asciidoc(path)`. Plain text. Strip attribute lines (`:key: value`), block delimiters, comment blocks (`////`), macros.

**Completion criteria**: Test with header, attributes, blocks, prose. **Files**: `helpers.rs`

---

## Phase 2: Format Intelligence — Revision Detection

All dispatched from `has_track_changes()` match arm. Same integration pattern as word count.

### T-011: ODT track changes

**What**: `"odt" => has_odt_revisions(path)`. Use `read_zip_entry_as_str(path, "content.xml")`. Check for `<text:tracked-changes` or `<text:change`.

**Completion criteria**: Two tests: clean ODT, ODT with tracked changes. **Files**: `helpers.rs`

---

### T-012: Fountain revision markers

**What**: `"fountain" => has_fountain_revisions(path)`. Check for `[[` (notes) or `/*` (boneyard) in file content.

**Completion criteria**: Two tests: clean script, script with notes. **Files**: `helpers.rs`

---

### T-013: LaTeX revision markers

**What**: `"tex" | "latex" => has_tex_revisions(path)`. Check for `\todo{`, `\fixme{`, `\added{`, `\deleted{`, `\replaced{`, `\hl{` (common revision packages).

**Completion criteria**: Test with `\todo{fix}` and clean document. **Files**: `helpers.rs`

---

## Phase 3: Format Intelligence — Structural Fingerprinting

### T-014: Fountain scene fingerprinting

**What**: `parse_fountain_scene_fingerprint(path) -> Option<String>`. Fountain scene headings: lines starting with `INT.`/`EXT.`/`INT./EXT.`/`I/E.` (case-insensitive) or `.` (forced). Read as plain text, collect headings, build canonical `"{count}:{h1}:{h2}:..."` → BLAKE3 hex.

Wire into `build_event()` context_note enrichment block (line ~1890), alongside the existing FDX fingerprint call. The check should be: if extension is `.fountain`, call this instead of `parse_fdx_scene_fingerprint`.

**Completion criteria**:
- Deterministic hash for same scene structure
- Handles standard and forced headings; ignores title page, notes, boneyard
- Test with 3-scene script
- Wired into `build_event()` as `fountain_scene_fp:<hash>`

**Files**: `helpers.rs`, `mod.rs` (re-export)

---

### T-015: Scrivener binder structure snapshot

**Audit (2026-06-18)**: `parse_scrivener_project_map()` (helpers.rs:2630) already parses `.scrivx` binder items — but it produces a **flat** `ScrivenerProjectMap` (`HashMap<UUID, Title>`) with no nesting depth or item type. The evidence packet's `DocumentStructureSnapshot` (evidence/types.rs:426) needs `Vec<DocumentStructureEntry>` with `uuid`, `title`, `depth: u32`, and `item_type: String`. So T-015 is NOT redundant — but the parsing work is 80% done. This task should **extend the existing parser**, not write a second one.

**What**: Add `parse_scrivener_binder_snapshot(path: &Path) -> Option<DocumentStructureSnapshot>` that reuses `find_scrivx_file()` and the existing tag-scanning technique from `parse_scrivener_project_map()`, but additionally:
1. Tracks nesting depth by counting `<BinderItem>` opens vs `</BinderItem>` closes
2. Extracts the `Type` attribute from each `<BinderItem>` tag (e.g. `Type="Text"`, `Type="Folder"`)
3. Returns `DocumentStructureEntry` vec instead of `HashMap`

Do NOT modify `parse_scrivener_project_map()` — it's used for session-level segment correlation (different purpose). The new function is a sibling, not a replacement.

Wire into checkpoint building for Scrivener sessions: when building the evidence packet, if the session has a `.scriv` path, call this to populate `Packet.document_structure`.

**Completion criteria**:
- Returns `DocumentStructureSnapshot` with correct nesting depth and item types
- Test with minimal XML containing 3 nested binder items (Folder > Text > Text)
- Reuses `find_scrivx_file()` (no duplicate path logic)
- `parse_scrivener_project_map()` unchanged and still works
- Integrated into checkpoint/evidence builder

**Files**: `helpers.rs`, `core_session.rs`, `evidence/types.rs` (read-only)

---

### T-016: OPML outline fingerprinting

**What**: `parse_opml_outline_fingerprint(path) -> Option<String>`. Parse `<outline text="...">` elements with nesting depth. Build canonical `"{count}:{d0:t0}:{d1:t1}:..."` → BLAKE3 hex.

Wire into `build_event()` for `.opml` files.

**Completion criteria**: Deterministic fingerprint, test with 4-item nested OPML. **Files**: `helpers.rs`

---

### T-017: Generalize fingerprint dispatch in build_event()

**Audit (2026-06-18)**: The `build_event()` enrichment block (helpers.rs:1882-1901) currently does three things per checkpoint for real files: `extract_word_count()` → `wc:N`, `has_track_changes()` → `track_changes:true`, and `parse_fdx_scene_fingerprint()` → `fdx_scene_fp:HASH`. The FDX fingerprint call is on lines 1891-1893 — the exact replacement point for this dispatcher.

**Problem**: The current enrichment block (line 1891) hardcodes `parse_fdx_scene_fingerprint`. After T-014 and T-016, we'll have 3 fingerprint functions with extension-specific dispatch. Don't add 3 separate `if let` blocks.

**What**: Create a dispatcher:
```rust
fn structural_fingerprint(path: &Path) -> Option<(&'static str, String)> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "fdx" => parse_fdx_scene_fingerprint(path).map(|fp| ("fdx_scene_fp", fp)),
        "fountain" => parse_fountain_scene_fingerprint(path).map(|fp| ("fountain_scene_fp", fp)),
        "opml" => parse_opml_outline_fingerprint(path).map(|fp| ("opml_outline_fp", fp)),
        _ => None,
    }
}
```

Replace the hardcoded `parse_fdx_scene_fingerprint` call in `build_event()` with:
```rust
if let Some((key, fp)) = structural_fingerprint(file_path) {
    extra.push(format!("{key}:{fp}"));
}
```

This makes adding future fingerprint formats a one-line change to the match arm.

**Completion criteria**:
- Existing FDX fingerprint behavior unchanged
- Fountain and OPML fingerprints appear in context_note
- Adding a new fingerprint format requires only adding a match arm
- Test: verify FDX still produces `fdx_scene_fp:...` in context_note

**Files**: `helpers.rs` (build_event block, new dispatcher function)

---

## Phase 4: Bundle Monitoring

### T-018: Vellum bundle monitoring

**Research (2026-06-18, deep search)**: Exhaustive search across Vellum help docs, blog, FAQ, MacUpdate, Softpedia, app catalogs, and developer forums. Key findings:

1. **Vellum 3.2 (May 2022) eliminated the package format.** Per [Vellum Blog](https://blog.vellum.pub/2022/05/vellum-3-2/): "Vellum documents are now just a single file and no longer use the Mac's package format." Before 3.2, `.vellum` was a macOS package directory. After 3.2, it's a single flat file. Conversion is automatic on save.
2. **Bundle ID is `co.180g.Vellum`** (not `com.180g.vellum` as we currently have in `app_registry.rs`). Developer ID: `5KKYLJ96NW`. Confirmed via [MacUpdate](https://vellum.macupdate.com/), [macupdater.net](https://macupdater.net/app_updates/appinfo/co.180g.Vellum/index.html), and [appcatalog.cloud](https://appcatalog.cloud/apps/vellum).
3. **No public documentation exists** for the internal structure of either format (old package or new flat file). No UTI declarations, no schema docs.
4. **Current version**: 4.1.3, requires macOS 13.5+, Universal Binary.

**Implications**: Since Vellum 3.2+ uses a flat file (not a package), `BUNDLE_EXTENSIONS` monitoring is **wrong** for current Vellum. A `.vellum` file is opaque — `start_bundle_monitor()` would fail because there's no directory to watch. Vellum saves are detected as regular file writes via Endpoint Security, same as Pages or Word.

Users on Vellum < 3.2 (pre-May 2022) would have package-format `.vellum` files, but that's 4+ years old. Not worth supporting the legacy package format.

**What**: Two changes:

1. **Fix bundle ID**: In `app_registry.rs`, change `"com.180g.vellum"` → `"co.180g.Vellum"`. This is a bug — the current ID won't match any real Vellum installation. Also add the old `com.180g.vellum` as a legacy alias in case any older Vellum versions used it.

2. **Do NOT add `"vellum"` to `BUNDLE_EXTENSIONS`**. Vellum 3.2+ saves flat files, not packages. The existing file-write detection path (Endpoint Security → `ffi_sentinel_es_file_write`) handles Vellum saves correctly once the bundle ID is fixed and T-001 removes the adapter gate.

**Completion criteria**:
- `lookup("co.180g.Vellum")` returns Vellum metadata
- `adapter_for_bundle("co.180g.Vellum")` returns `Some(VellumAdapter)`
- Legacy `adapter_for_bundle("com.180g.vellum")` still works (alias)
- `is_bundle_document(Path::new("novel.vellum"))` returns `false` (it's a flat file now)
- Update tests

**Files**: `app_registry.rs`

---

### T-019: Heuristic macOS package detection

**What**: When a new file path arrives with an unrecognized extension, check if it's a macOS package directory:
```rust
fn is_macos_package(path: &Path) -> bool {
    path.is_dir() && path.join("Contents").is_dir()
}
```

Use as fallback in sentinel path handling after `is_bundle_document()` returns false. If detected, treat as bundle document and attempt to find a content subdirectory using `CONTENT_SUBDIRS`.

**Completion criteria**:
- Detects arbitrary package directories (requires `Contents/`)
- Does NOT false-positive on regular directories
- Test with mock package

**Files**: `bundle_monitor.rs`, `core_session.rs`

---

## Phase 5: App Adapters (Batch)

### T-020: Batch adapter additions + Ulysses update

Only add adapters where they provide `is_compile_process` knowledge for export attestation. After T-001, this is a confidence upgrade, not a requirement.

| App | Bundle ID | Compile/Export Processes |
|-----|-----------|------------------------|
| Highland 2 | `com.quoteunquoteapps.highland2` | `"Highland 2"` |
| Pages | `com.apple.iWork.Pages` | `"Pages"` |
| Obsidian | `md.obsidian` | `"Obsidian"`, `"Obsidian Helper"` |
| Bear | `net.shinyfrog.bear` | `"Bear"` |
| DEVONthink 3 | `com.devon-technologies.think3` | `"DEVONthink 3"`, `"DEVONagent"` |

Update `UlyssesAdapter.is_compile_process()` to also match `"Ulysses Publishing"`.

All adapters: `internal_docs_path()` → `None`. All follow existing adapter pattern (struct + impl + register in `adapter_for_bundle()`).

**Completion criteria**: 5 new adapters + 1 update, tests for each. **Files**: `app_registry.rs`

---

## Phase 6: iCloud & Cloud Sync Resilience

### T-021: Skip iCloud placeholder files

**What**: iCloud creates `.filename.ext.icloud` placeholders (binary plist, no document content). Add:
```rust
pub fn is_icloud_placeholder(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.starts_with('.') && name.ends_with(".icloud")
}
```

Integrate into `build_event()` — skip enrichment for placeholders. Also integrate into `compute_file_hash()` — return an error for placeholders instead of hashing a plist.

**Completion criteria**: Placeholder detected and skipped; real files unaffected; test for both.

**Files**: `helpers.rs`, `core_session.rs`

---

### T-022: Detect iCloud conflict copies

**What**: iCloud conflict copies use a specific naming pattern (verified 2026-06-18):
```
filename (DeviceName - YYYY-MM-DD).ext
```
Example: `document (David's MacBook Pro - 2026-06-18).docx`

This is the ONLY reliable conflict pattern. Previously considered patterns that are NOT conflicts:
- `filename 2.ext` — Finder duplicates or app auto-naming (TextEdit `Untitled 2.rtf`). NOT iCloud.
- `filename (text).ext` — Legitimate parentheticals in titles (e.g. `Synthesis of methylamine hcl (large scale).md`).

Add detection:
```rust
pub fn is_icloud_conflict_copy(path: &Path) -> bool {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    // Pattern: " (DeviceName - YYYY-MM-DD)" at end of stem
    if let Some(paren_start) = stem.rfind(" (") {
        let inside = &stem[paren_start + 2..];
        if let Some(close) = inside.rfind(')') {
            let content = &inside[..close];
            // Must contain " - " followed by a date-like pattern (4 digits - 2 digits - 2 digits)
            if let Some(dash_pos) = content.rfind(" - ") {
                let date_part = &content[dash_pos + 3..];
                return date_part.len() == 10
                    && date_part.as_bytes().get(4) == Some(&b'-')
                    && date_part.as_bytes().get(7) == Some(&b'-')
                    && date_part.bytes().filter(|b| b.is_ascii_digit()).count() == 8;
            }
        }
    }
    false
}
```

When detected, annotate `icloud_conflict:true` in context_note via `build_event()`.

**Completion criteria**:
- `is_icloud_conflict_copy("doc (David's MacBook Pro - 2026-06-18).docx")` → `true`
- `is_icloud_conflict_copy("Untitled 2.rtf")` → `false`
- `is_icloud_conflict_copy("Synthesis (large scale).md")` → `false`
- `is_icloud_conflict_copy("chapter.md")` → `false`
- Context note includes `icloud_conflict:true` when detected
- Tests for all four cases above

**Files**: `helpers.rs`

---

## Phase 7: Export Format Coverage

### T-028: Tiered export detection with process-matching

**Problem**: `EXPORT_EXTENSIONS` in `helpers.rs:2619` contains only 5 formats: `docx`, `pdf`, `epub`, `rtf`, `odt`. Real writing apps export to 18+ formats. But naively adding `.txt`, `.html`, `.md` to the list creates serious false positives:

- User writes in Obsidian. Slack writes `message.html` to cache. 30-second window, keystrokes > 0. **False positive.**
- User writes in Pages. Xcode builds `output.txt`. **False positive.**
- User writes in iA Writer. Safari downloads `paper.pdf`. **False positive.**

The 30-second window + keystroke count filter out idle sessions but NOT other active processes writing common file types. With 5 exotic extensions the collision odds were low. With 18 including `txt`/`html`/`md` it's a real problem.

**The key signal we're ignoring**: `ffi_sentinel_es_file_write` receives `signing_id` — the process that wrote the file. When Pages exports to `.txt`, the `signing_id` IS Pages. When Xcode writes `output.txt`, the signing_id is Xcode. We can use this.

**What**: Replace the single flat `EXPORT_EXTENSIONS` with a tiered system. The tiers control what evidence is needed, not what formats are recognized:

```rust
/// Formats that are almost exclusively created by deliberate export.
/// Guard: 30s window + keystrokes > 0 (existing behavior).
const EXPORT_TIER1: &[&str] = &[
    "docx", "epub", "mobi", "odt", "pages", "rtf",
];

/// Formats that are commonly created by many processes.
/// Guard: 30s window + keystrokes > 0 + signing_id must match session's app.
const EXPORT_TIER2: &[&str] = &[
    "doc", "dvi", "fdx", "fountain", "html", "md", "mmd",
    "opml", "pdf", "ps", "tex", "txt",
];

/// Image formats — only attested when the writing app itself wrote the file.
/// Guard: 30s window + keystrokes > 0 + signing_id must match session's app.
const EXPORT_TIER3_IMAGE: &[&str] = &[
    "jpg", "jpeg", "png", "tiff",
];
```

The signing_id comparison extracts the bundle ID portion (`signing_id.split(':').next_back()`) and compares case-insensitively against `session.app_bundle_id`. This is the same extraction already done at line 66.

**Why PDF is Tier 2, not Tier 1**: We verified (2026-06-18) that macOS Save-as-PDF is in-process — Pages writes the PDF, so the signing_id matches. But Safari downloading a PDF, or Preview saving a PDF, would also have a valid signing_id. The process-match guard correctly differentiates: Safari's signing_id won't match an Obsidian session, so a browser PDF download won't trigger a false attestation against a writing session.

**Export vs Save**: Some Tier 2 extensions (`.txt`, `.md`, `.fountain`) are also native save formats. This is handled correctly because `ffi_sentinel_es_file_write` checks `tracked_files` first (line 40) and returns early for tracked documents. A normal save to `essay.md` hits the checkpoint path. Only NEW files reach the export detection path.

Refactor `detect_export_event()` to accept an `ExportTier` parameter (or the signing_id + session bundle_id, letting it perform the match internally). The tier is determined by the caller based on extension.

**Completion criteria**:
- Tier 1: `.epub` export from any focused session → attestation (no process match needed)
- Tier 2: `.txt` written by Pages (signing_id matches) while Pages session active → attestation
- Tier 2: `.txt` written by Xcode while Pages session active → NO attestation (signing_id mismatch)
- Tier 2: `.pdf` written by Pages (signing_id matches) → attestation
- Tier 2: `.pdf` downloaded by Safari while user writes in Obsidian → NO attestation
- Tier 3: `.png` written by Pages → attestation; screenshot by screencaptureui → NO attestation
- Adapter high-confidence path: Scrivener compile process writes `.pdf` → attestation (adapter match overrides tier)
- Test: each tier with matching and non-matching signing_id
- Binary search on sorted lists

**Files**: `crates/cpoe/src/sentinel/helpers.rs`, `crates/cpoe/src/ffi/sentinel_es.rs`

---

### T-029: Export format and confidence annotation in ManuscriptExportAttestation

**Problem**: The current `ManuscriptExportAttestation` records that an export happened but not what format or how confident the correlation is. A PDF export and a plain text export from the same session are indistinguishable. And after T-028 introduces tiered detection, the tier/confidence level should be recorded in the attestation for downstream forensic analysis.

**What**: Add two fields to `ManuscriptExportAttestation`:

```rust
pub struct ManuscriptExportAttestation {
    // ... existing fields ...
    /// The export file extension (e.g. "pdf", "epub", "txt").
    pub export_format: String,
    /// How the export was correlated to the session.
    /// "high" = adapter compile-process match.
    /// "process_match" = signing_id matches session bundle (tier 2/3).
    /// "time_window" = tier 1 extension within time window only.
    pub correlation_method: String,
}
```

Populate from the extension and tier already determined in the detection path. Wire format: add new CBOR keys in the evidence map. Make both fields optional during deserialization for backward compatibility.

**Completion criteria**:
- `export_format` and `correlation_method` populated in all new attestations
- Old attestations without these fields deserialize cleanly (empty string or None)
- Adapter-matched exports get `correlation_method: "high"`
- Process-matched tier 2 exports get `correlation_method: "process_match"`
- Tier 1 exports get `correlation_method: "time_window"`
- Test: verify both fields present in attestation output
- Wire format keys documented

**Files**: `crates/cpoe/src/evidence/types.rs`, `crates/cpoe/src/sentinel/helpers.rs`, CBOR serialization in `crates/authorproof-protocol/`

---

## Phase 8: File Extensions

### T-023: Expand DOC_EXTENSIONS

**What**: Add missing extensions to the sorted `DOC_EXTENSIONS` array in `types.rs`. These enable `looks_like_file_path()` to recognize titles containing these extensions, which enables title-based session tracking for apps using these formats.

Extensions to add (verified not already present):
```
.ass        — Advanced SubStation subtitle
.bear       — Bear note export
.creole     — Creole wiki markup
.djot       — Djot markup
.highland   — Highland 2 native
.ink        — Inkle interactive fiction
.ipynb      — Jupyter notebook
.lyx        — LyX document
.markua     — Markua (Leanpub)
.mermaid    — Mermaid diagram
.qmd        — Quarto document
.rmd        — R Markdown
.srt        — SRT subtitle
.tbx        — Tinderbox
.textile    — Textile markup
.tw         — Twine interactive fiction
.twee       — Twee source
.typ        — Typst
.ulyz       — Ulysses export
.vtt        — WebVTT subtitle
```

Verify the array remains sorted (binary search depends on it). Add a test that asserts sorted order.

**Completion criteria**: All extensions added in sorted order; `looks_like_file_path("novel.highland")` returns `true`; sorted-order assertion test.

**Files**: `crates/cpoe/src/sentinel/types.rs`

---

## Phase 8: Auto-Discovery Improvements

### T-024: Expand NON_WRITING_BUNDLES exclusion list

**What**: Add ~10 common non-writing apps that waste probe cycles:
```rust
"com.apple.TV",
"com.apple.podcasts",
"com.apple.Preview",
"com.apple.FaceTime",
"us.zoom.xos",
"com.microsoft.teams2",
"com.tinyspeck.slackmacgap",
"com.apple.ScreenSharing",
"com.apple.QuickTimePlayerX",
"com.apple.Image_Capture",
```

Note: Browsers and terminals intentionally NOT excluded (Google Docs, web editors, terminal vim).

**Completion criteria**: Entries added; no legitimate writing app excluded.

**Files**: `app_registry.rs`

---

### T-025: Auto-discovery confidence decay

**What**: Auto-discovered apps persist forever in `user_apps.json` at their original confidence level. Add:
1. `last_seen_at` field to `UserWritingApp` (updated on each session start)
2. On load: demote apps not seen in 90 days (`High` → `Medium` → `Low`)
3. On load: remove `Low` confidence apps not seen in 180 days
4. Schema version bump with migration

**Completion criteria**: Stale apps demoted/pruned; schema migration works; test.

**Files**: `app_registry.rs`

---

## Phase 9: Robustness

### T-026: Format version robustness audit

**What**: Ensure all format functions handle unexpected file contents gracefully:
- A `.docx` that's actually plain XML (corrupted save) → `None`, no panic
- A `.odt` with unexpected internal structure → `None`
- A renamed `.txt` with `.fdx` extension → `None`

Audit: `extract_word_count` (all branches), `has_track_changes` (all branches), all fingerprint functions. Each must peek at content before assuming format. The `read_xml_content` utility from T-000 already does this for ZIP-or-plain detection.

Add test: renamed `.txt` files with misleading extensions → `None` for each.

**Completion criteria**: No format function panics on unexpected content; test with misnamed files.

**Files**: `helpers.rs`

---

### T-027: Rate-limit auto-discovery probing

**What**: `probe_and_cache()` spawns a thread per unknown app. With many apps open, this could mean 20+ probe threads at checkpoint time. Add:
1. Per-checkpoint cap: max 3 probes per checkpoint cycle
2. Cooldown: don't re-probe a timed-out bundle ID for 5 minutes
3. Track timed-out probes separately from successful ones

**Completion criteria**: Max 3 probes per checkpoint; timed-out probes cooldown; test.

**Files**: `app_registry.rs`

---

## Phase 10: Paste Detection & Scoring Fixes

### T-030: Fix `keystroke_count_after_paste` never incremented (BUG)

**Problem**: `PasteContext.keystroke_count_after_paste` is initialized to 0 in `update_keystroke_context_window()` (helpers.rs:1510) and read by `classify_paste()` (composition_mode.rs:187-193) where:
- ≥20 keystrokes = Domesticated (weight 0.5, genuine editing)
- ≤5 keystrokes = Veneer (weight 0.1, suspicious)
- 6-19 = Moderate (no extra penalty)

But the field is **never incremented anywhere**. Grep confirms: no `+= 1`, no `.saturating_add(1)`, no mutation outside initialization. Every paste scores as Veneer (0 ≤ 5), applying the harshest penalty. A user who pastes a citation then spends 10 minutes editing around it gets the same score as someone who pastes an AI-generated essay and hits save.

This is the single most impactful bug in the paste system.

**Exact location**: `ffi/sentinel_inject.rs:419-421`. This is the ONLY place `session.keystroke_count` is incremented:

```rust
if semantic.is_content_producing() {
    session.keystroke_count = session.keystroke_count.saturating_add(increment);
}
// INSERT PASTE COUNTER INCREMENT HERE
```

**What**: After line 421, add:

```rust
if let Some(ref mut ctx) = session.paste_context {
    if timestamp_ns < ctx.context_window_end {
        ctx.keystroke_count_after_paste = ctx
            .keystroke_count_after_paste
            .saturating_add(increment as usize);
    }
}
```

Note: `increment` is `coalesced_count.max(1)` (u64), already computed at line 418. Use the same value so coalesced keystrokes count correctly.

**Completion criteria**:
- After paste + 25 keystrokes within window → `keystroke_count_after_paste == 25`
- `classify_paste()` returns `Domesticated` for that context
- After paste + 3 keystrokes → returns `Veneer`
- After paste window expires → counter stops incrementing
- Test: verify counter increments, verify composition mode classification changes

**Files**:
- `crates/cpoe/src/ffi/sentinel_inject.rs` — after line 421
- Verify integration with `composition_mode.rs` (read-only — scoring logic is correct, just never gets non-zero input)

---

### T-039: Accumulate paste history instead of overwriting

**Problem**: `DocumentSession` has a single `paste_context: Option<PasteContext>` field (types.rs:1161). Each new paste overwrites the previous one. But `analyze_composition_mode()` (composition_mode.rs:276) takes `paste_contexts: &[PasteContext]` — a slice of ALL paste events for forensic scoring.

The scoring function expects a history of paste events to compute mode distribution (what fraction were veneer vs domesticated). With only the last paste surviving, the analysis is based on a single data point regardless of how many pastes occurred in the session.

A session with 10 pastes — 9 veneer + 1 domesticated at the end — would score as fully domesticated because only the last paste is seen.

**What**: Change `DocumentSession.paste_context` from `Option<PasteContext>` to `Vec<PasteContext>`. When a new paste is detected:
1. If the current `paste_context` has a non-expired window, finalize it (freeze `keystroke_count_after_paste`) and push to the history vec
2. Start a new `PasteContext` for the incoming paste
3. At forensic analysis time, pass the full vec to `analyze_composition_mode()`

Cap the vec at 100 entries (beyond that, forensic analysis has more than enough data) to prevent memory growth in pathological cases.

**Completion criteria**:
- 5 pastes in a session → `session.paste_history.len() == 5`
- All 5 paste contexts available to forensic analysis with accurate keystroke counts
- Most recent paste context accessible for `is_within_paste_window()` checks
- Vec capped at 100 entries
- Test: multiple pastes → all preserved; forensic analysis receives full history

**Files**:
- `crates/cpoe/src/sentinel/types.rs` — `DocumentSession` field change
- `crates/cpoe/src/sentinel/helpers.rs` — `update_keystroke_context_window()`, `is_within_paste_window()`
- `crates/cpoe/src/sentinel/event_handlers.rs` — callers that read `paste_context`
- `crates/cpoe/src/sentinel/core_session.rs` — checkpoint building (passes paste context to forensics)

---

### T-031: Fix phantom paste from file hash discontinuity

**Problem**: In `handle_change_event_sync` (helpers.rs:819-842), paste detection calls `detect_paste_boundary()` with the same bundle ID for both `app_focused_at_time` and `previous_focused_app` (line 824-825):

```rust
let (context, confidence) = detect_paste_boundary(
    last_ts, current_ts,
    &prev_hash, &new_hash,
    &session.app_bundle_id,  // current app
    &session.app_bundle_id,  // "previous" app — ALWAYS THE SAME
);
```

Signal 3 (app transition) can never fire because both args are identical. The detector is effectively 2-signal, and the confidence threshold is 0.80. This means:
- Auto-save after 500ms idle → signal 1 (time gap) + signal 2 (hash change) → confidence 0.85 → **phantom paste**
- Find-and-replace → hash changes, user pauses to type replacement text → phantom paste
- iCloud sync replacing file → hash changes → phantom paste
- Undo/redo → hash reverts → phantom paste

Any file modification after 500ms of inactivity triggers a false paste detection.

**What**: Two changes:

1. Pass the actual previous focused app bundle ID instead of the session's own ID. The sentinel tracks focus transitions — use `session.previous_focused_app` or equivalent. If no previous app is tracked, pass an empty string (which will match the current app, making signal 3 impossible — same as today but explicitly correct rather than accidentally broken).

2. Raise the confidence threshold at this call site from 0.80 to 0.92. The file-hash-based detection path is inherently noisier than the FFI path (which gets explicit paste notification from macOS). At 0.92, only 2-signal cases with >2000ms gaps fire — these are more likely real pastes. The FFI path handles the rest.

3. Don't hardcode `PasteContentKind::Prose` (line 840). This call site has no clipboard info, so use `PasteContentKind::default()` (which is `Prose`, but makes the intent clear) and add a comment that the FFI path will override with accurate classification if it fires for the same event.

**Completion criteria**:
- Auto-save after 600ms idle does NOT trigger paste detection
- Large file change after 3000ms with actual app switch DOES trigger paste detection
- Confidence threshold enforced at 0.92 for this call site
- Test: simulate auto-save timing pattern → no paste context set

**Files**: `crates/cpoe/src/sentinel/helpers.rs` (lines 819-842)

---

### T-032: Deduplicate paste recording between Rust and FFI paths

**Problem**: Two independent systems detect the same paste event:
- **Path A** (Rust, helpers.rs:819): File hash discontinuity + timing → sets `session.paste_context` with 5-second window, `PasteSource::Unknown`, `PasteContentKind::Prose`
- **Path B** (FFI, text_fragment.rs:524): macOS `NSPasteboard` observation → sets `session.paste_context` with 30-second window, accurate `PasteSource` from store lookup, accurate `PasteContentKind` from text analysis

Path B always fires ~50-200ms after Path A (FFI call crosses the Swift→Rust boundary). Path B overwrites Path A's context entirely, resetting `keystroke_count_after_paste` to 0 (losing any keystrokes counted between the two firings).

**What**: In `update_keystroke_context_window()` (helpers.rs:1496), if `session.paste_context` already exists and the new paste_time is within 2 seconds of the existing one, **merge** rather than overwrite:
- Keep the existing `keystroke_count_after_paste` (don't reset to 0)
- Take the better data: use the new `source` if it's not `Unknown`, use the new `content_kind` if the new path has pasteboard type info
- Use the longer `context_window_end` (FFI's 30s > Rust's 5s)

```rust
if let Some(ref mut existing) = session.paste_context {
    let delta_ns = paste_time.saturating_sub(existing.paste_time).unsigned_abs();
    if delta_ns < 2_000_000_000 {
        // Merge: keep keystroke count, upgrade metadata
        if source != PasteSource::Unknown {
            existing.source = source;
        }
        if content_kind != PasteContentKind::Prose || existing.content_kind == PasteContentKind::Prose {
            existing.content_kind = content_kind;
        }
        existing.context_window_end = existing.context_window_end.max(
            paste_time.saturating_add(window_nanos)
        );
        return;
    }
}
```

**Completion criteria**:
- Rapid double-detection (Rust then FFI within 2s) merges into single paste context
- Keystroke count preserved across merge
- Source upgraded from `Unknown` to actual classification
- Window extended to longer duration
- Truly separate pastes (>2s apart) still create new contexts
- Test: simulate Rust path, then FFI path 100ms later → single context with merged data

**Files**: `crates/cpoe/src/sentinel/helpers.rs` (update_keystroke_context_window)

---

### T-033: Fix wrong bundle IDs in clipboard monitor default apps

**Problem**: `default_monitored_apps()` in clipboard.rs:50-61 has incorrect bundle IDs:

| Listed | Correct | Issue |
|--------|---------|-------|
| `com.ulysses` | `com.ulyssesapp.mac` | Wrong — will never match |
| `com.bear` | `net.shinyfrog.bear` | Wrong — will never match |
| `com.dayoneapp` | `com.bloombuilt.dayone-mac` | Wrong — will never match |
| `com.google.docs` | N/A | Google Docs is a web app (runs in browser), not a native app — this bundle ID doesn't exist on macOS |

4 of the 8 default monitored apps are dead entries. The clipboard monitor only actually works for Apple Notes, Pages, Word, and Scrivener.

**What**: Fix the bundle IDs and add a few high-value apps:

```rust
fn default_monitored_apps() -> Vec<String> {
    vec![
        "com.apple.Notes".to_string(),
        "com.apple.iWork.Pages".to_string(),
        "com.microsoft.Word".to_string(),
        "com.ulyssesapp.mac".to_string(),
        "com.literatureandlatte.scrivener3".to_string(),
        "net.shinyfrog.bear".to_string(),
        "com.bloombuilt.dayone-mac".to_string(),
        "md.obsidian".to_string(),
    ]
}
```

Remove `com.google.docs` — Google Docs runs in a browser; clipboard monitoring for it would require matching browser bundle IDs (Safari, Chrome), which is a different problem.

**Completion criteria**:
- All listed bundle IDs match actual macOS app bundle identifiers
- `verify_paste_source_bundle_id("com.ulyssesapp.mac")` returns `true`
- `verify_paste_source_bundle_id("com.ulysses")` returns `false`
- Test: verify each default ID matches a known app in the registry

**Files**: `crates/cpoe/src/sentinel/clipboard.rs`

---

### T-034: Make clipboard monitor use app registry instead of hardcoded list

**Problem**: The clipboard monitor hardcodes 8 apps (4 of which are wrong per T-033). Meanwhile the app registry has 109 builtins + user-added + auto-discovered apps. Any paste in a non-monitored app gets no copy-side evidence.

**What**: Replace `default_monitored_apps()` with a call to the app registry. In `verify_paste_source_bundle_id()`, instead of checking against a static list, check `app_registry::is_known(bundle_id)`:

```rust
pub fn verify_paste_source_bundle_id(
    &self,
    bundle_id: &str,
) -> std::result::Result<bool, ClipboardError> {
    if bundle_id.is_empty() {
        return Ok(false);
    }
    Ok(crate::sentinel::app_registry::is_known(bundle_id))
}
```

Keep `MAX_MONITORED_APPS` as a safety cap (the check is per-event, not per-app — it just asks "is this app a writing app?"). The `monitored_apps` field and its `RwLock` can be removed entirely.

**Completion criteria**:
- Clipboard events from any registered writing app are captured
- Clipboard events from non-writing apps (Finder, Spotify) are ignored
- Auto-discovered apps are included
- No performance regression (registry lookup is O(n) over ~109 apps, called at most once per 100ms)
- Test: mock paste from app in registry → captured; from non-writing app → ignored

**Files**: `crates/cpoe/src/sentinel/clipboard.rs`

---

### T-035: Pass PasteboardTypeInventory through FFI paste recording

**Problem**: `ffi_sentinel_record_paste()` (text_fragment.rs:449-454) creates an empty `PasteboardTypeInventory::default()` because the FFI function doesn't accept pasteboard type parameters. Content classification from FFI is text-only — no UTI signals for image detection, spreadsheet detection, or format-only detection.

The Swift app has direct access to `NSPasteboard.types` at paste time. This data is lost at the FFI boundary.

**What**: Add pasteboard type parameters to `ffi_sentinel_record_paste()`:

```rust
pub fn ffi_sentinel_record_paste(
    char_count: i64,
    pasted_text: String,
    timestamp_ns: i64,
    app_bundle_id: String,
    window_title: String,
    detection_confidence: f64,
    has_plain_text: bool,
    has_rtf: bool,
    has_html: bool,
    has_image: bool,
    has_spreadsheet: bool,
) -> FfiPasteRecordResult
```

Construct `PasteboardTypeInventory` from the booleans. Pass to `classify_paste_content_kind()`. This gives the FFI path the same classification quality as the clipboard monitor.

**Completion criteria**:
- Image paste from FFI classified as `Media` (not `Prose`)
- Table paste from FFI classified as `StructuredData`
- Existing callers in Swift updated to pass pasteboard type booleans
- Test: FFI call with `has_image: true, pasted_text: ""` → `Media` classification

**Files**:
- `crates/cpoe/src/ffi/text_fragment.rs` — function signature + inventory construction
- `apps/cpoe_macos/` — Swift caller update (pass `NSPasteboard.types` checks)

---

### T-036: Scale paste domestication threshold by paste size

**Problem**: `classify_paste()` in composition_mode.rs:187-193 uses a fixed threshold:
- ≥20 keystrokes after paste = Domesticated (weight 0.5)
- ≤5 keystrokes = Veneer (weight 0.1)

This doesn't scale. Pasting 5000 words and adding 20 keystrokes (4 corrections) is veneer, not domestication. Pasting 10 words and adding 20 keystrokes is genuine editing.

**What**: Scale the domestication threshold by paste character count. Add `paste_char_count: usize` to `PasteContext` (set from `char_count` in FFI, or estimated from hash change size in Rust path). Then:

```rust
let domestication_threshold = (paste.paste_char_count / 50).max(20).min(200);
let class = if paste.keystroke_count_after_paste >= domestication_threshold {
    PasteClass::Domesticated
} else if paste.keystroke_count_after_paste <= 5 {
    PasteClass::Veneer
} else {
    PasteClass::Moderate
};
```

Rationale: ~50 chars per meaningful edit (rephrase a sentence, fix a paragraph). A 5000-char paste needs ~100 edits to be genuinely domesticated. Cap at 200 to avoid absurd thresholds for very large pastes.

**Completion criteria**:
- 50-char paste + 20 keystrokes = Domesticated
- 5000-char paste + 20 keystrokes = Moderate (not Domesticated)
- 5000-char paste + 100 keystrokes = Domesticated
- Cap at 200 keystrokes regardless of paste size
- `PasteContext` gains `paste_char_count` field
- FFI path sets it from `char_count` parameter
- Rust path sets it to 0 (unknown — falls back to default threshold of 20)
- Test: verify scaling at multiple paste sizes

**Files**:
- `crates/cpoe/src/sentinel/types.rs` — `PasteContext` struct
- `crates/cpoe/src/sentinel/helpers.rs` — `update_keystroke_context_window()`
- `crates/cpoe/src/ffi/text_fragment.rs` — pass char_count to context
- `crates/cpoe/src/forensics/composition_mode.rs` — `classify_paste()`

---

### T-037: Supplement static AI tool list with heuristic detection

**Problem**: `KNOWN_AI_APP_BUNDLE_IDS` in `constants.rs` lists 18 AI tools. New AI tools launch constantly — the list will always be incomplete. Missing an AI tool means AI-mediated cycles go undetected, inflating evidence scores for AI-generated content.

**What**: Add a heuristic fallback after the static list check. In the function that calls `is_ai_tool_bundle_id()` (or in the function itself), also check:

```rust
fn is_likely_ai_tool(bundle_id: &str, window_title: &str) -> bool {
    if KNOWN_AI_APP_BUNDLE_IDS.iter().any(|id| id.eq_ignore_ascii_case(bundle_id)) {
        return true;
    }
    let lower_bid = bundle_id.to_ascii_lowercase();
    let lower_title = window_title.to_ascii_lowercase();
    const AI_SIGNALS: &[&str] = &[
        "openai", "chatgpt", "claude", "anthropic", "gemini", "copilot",
        "gpt", "llm", "perplexity", "mistral", "cohere", "bard",
    ];
    AI_SIGNALS.iter().any(|s| lower_bid.contains(s) || lower_title.contains(s))
}
```

Guard against false positives: don't match on generic substrings like `"ai"` (matches `mail`, `repair`, `contain`). Only match on AI-specific product names and terms.

Flag heuristic matches differently from static matches in logs: `"Heuristic AI tool match: {bundle_id} (window: {title})"` so false positives can be reviewed and either added to the static list or excluded.

**Completion criteria**:
- `is_likely_ai_tool("com.newaitool.app", "")` returns `true` (contains "ai" — wait, no, we said don't match on "ai")
- `is_likely_ai_tool("com.unknown.app", "ChatGPT Plus")` returns `true` (window title)
- `is_likely_ai_tool("com.apple.mail", "Mail")` returns `false` (no match)
- `is_likely_ai_tool("io.github.nicegpt.app", "NiceGPT")` returns `true` (contains "gpt")
- Heuristic matches logged distinctly from static matches
- Test: verify static list still works; verify heuristic catches new tools

**Files**:
- `crates/cpoe/src/forensics/constants.rs` — `is_likely_ai_tool()` or modify `is_ai_tool_bundle_id()`
- `crates/cpoe/src/sentinel/clipboard.rs` — update caller if function signature changes

---

### T-038: Track paste character volume in evidence

**Problem**: `PasteContentBreakdown` (composition_mode.rs:106-113) counts paste events by content kind but doesn't capture total character volume. A session with 1 paste of 10,000 words looks the same as 1 paste of 10 words. Character volume is a strong forensic signal — especially for AI-mediated detection (large blocks pasted after AI app focus).

**What**: Add `total_chars_pasted: usize` to `PasteContentBreakdown`. Accumulate from `PasteContext.paste_char_count` (added in T-036) when computing the breakdown.

**Completion criteria**:
- `PasteContentBreakdown.total_chars_pasted` reflects cumulative paste character volume
- Evidence packets include the character count
- Test: 3 pastes of 100, 500, 1000 chars → total_chars_pasted = 1600

**Files**:
- `crates/cpoe/src/forensics/composition_mode.rs` — struct + computation
- `crates/cpoe/src/evidence/types.rs` — if breakdown is serialized into evidence

---

## Phase 11: Text Attestation Fixes

Issues 1 (isValidWAROutput) and 2 (VC signature DST) were fixed directly — see commits.

### T-042: Sync attestation block format between Rust engine and browser extension

**Problem**: The Rust engine (`text_fragment.rs:649-653`) produces a 4-line attestation block:
```
WritersProof Verified | ID: abc123 | 2026-06-18T12:00:00Z
Cryptographic authorship attestation with keystroke evidence.
VC-Sig: f<128-char hex>
verify.writersproof.com
```

The browser extension (`background.js:1571-1574`) produces a 3-line block — no `VC-Sig` line. Users get different attestation formats depending on macOS Services vs browser extension. The verification portal at `verify.writersproof.com` needs to handle both, but only one format is documented.

**What**: Add the VC-Sig line to the browser extension attestation block. The extension already has access to the signing key (via native messaging host or IndexedDB fallback). Generate the same `witnessd-vc-attest-v1:` prefixed signature.

Also: document the `f` prefix on `VC-Sig: f{sig}` — if it's a format version tag, add a comment. If it's accidental, remove it from both implementations before they diverge further.

**Completion criteria**:
- Browser extension and Rust engine produce identical 4-line format
- `f` prefix documented or removed
- Verification portal handles the format

**Files**: `apps/cpoe_browser_extension/background.js`, `crates/cpoe/src/ffi/text_fragment.rs`

---

### T-043: Capture actual window title for text attestation context

**Problem**: `CPoEServiceProvider.swift:356-360` captures `NSWorkspace.shared.frontmostApplication?.localizedName` (e.g. "Pages") as the `windowTitle` parameter. This is the app's display name, not the window title containing the document name. The Rust side stores it as `source_window_title`, which is misleading — a verifier sees "Pages" instead of "Chapter 3 — My Novel".

**What**: Use `NSAccessibility` or `CGWindowListCopyWindowInfo` to capture the actual title of the frontmost window. The app name is already available via `bundleId` lookup, so `windowTitle` should carry the document-identifying information.

```swift
let windowTitle: String = {
    guard let app = NSWorkspace.shared.frontmostApplication else { return "" }
    let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    return windows.first(where: { ($0[kCGWindowOwnerPID as String] as? Int32) == app.processIdentifier && ($0[kCGWindowLayer as String] as? Int) == 0 })?[kCGWindowName as String] as? String ?? ""
}()
```

Guard: strip the window title to just the document name portion (many apps format as "Document — AppName"). Only store the document portion.

**Completion criteria**:
- Attestation from Pages editing "Chapter 3" stores window title "Chapter 3" (not "Pages")
- Falls back to empty string if window title unavailable
- No privacy-sensitive paths leaked (strip to basename if title contains a full path)

**Files**: `apps/cpoe_macos/cpoe/App/CPoEServiceProvider.swift`

---

### T-044: Add minimum text length for attestation

**Problem**: `ffi_attest_text` (text_fragment.rs:554) checks max size (10 MB) but has no minimum. A single character "a" produces a valid attestation. This creates noise in the fragment store and provides zero forensic value.

**What**: After normalization, require at least 50 characters of attestable content. Return a clear error: "Text too short for attestation (minimum 50 characters after normalization)."

50 characters ≈ 8-10 words, which is the minimum that could plausibly carry authorship signal.

**Completion criteria**:
- 49 normalized chars → error with clear message
- 50 normalized chars → success
- Test both boundaries

**Files**: `crates/cpoe/src/ffi/text_fragment.rs`

---

## Dependency Graph

```
T-000 (ZIP utility extraction) ← CRITICAL PATH
├── T-004 (ODT wc) ← uses read_zip_entry_as_str
├── T-011 (ODT revisions) ← uses read_zip_entry_as_str
└── T-017 (fingerprint dispatch) ← restructures build_event block

T-001 (decouple export attestation) ← HIGHEST IMPACT (also covers Print-to-PDF; T-002 eliminated)
└── T-020 (adapters) ← less critical after T-001

T-003 (prefix matching) ← independent

T-005..T-010 (word count formats) ← independent of each other, no dependency on T-000

T-012..T-013 (revision detection) ← independent of each other

T-014 (Fountain fingerprint) ← independent
T-015 (Scrivener binder) ← independent
T-016 (OPML fingerprint) ← independent
T-017 (fingerprint dispatch) ← depends on T-014, T-016, and T-000

T-018..T-019 (bundle monitoring) ← independent
T-020 (adapters) ← independent (but lower priority after T-001)
T-021..T-022 (iCloud) ← T-022 depends on T-021
T-023 (extensions) ← independent
T-024..T-025 (discovery) ← independent
T-026..T-027 (robustness) ← T-026 depends on T-000; T-027 independent

T-028 (tiered export detection) ← depends on T-001
T-029 (export format/confidence annotation) ← depends on T-028

T-030 (keystroke counter bug) ← INDEPENDENT, CRITICAL BUG FIX
T-031 (phantom paste fix) ← independent
T-032 (paste dedup) ← depends on T-030 (counter must work before merge matters)
T-033 (clipboard monitor bundle IDs) ← independent, trivial
T-034 (clipboard monitor use registry) ← depends on T-033
T-035 (FFI pasteboard types) ← independent (FFI signature change)
T-036 (scaled domestication) ← depends on T-030 (counter must work first)
T-037 (AI tool heuristic) ← independent
T-038 (paste char volume) ← depends on T-036 (needs paste_char_count field)
T-039 (paste history accumulation) ← depends on T-030 (counter must work), enhances T-032
```

## Parallelization Groups

These can execute independently:

1. **ZIP foundation**: T-000, then T-004, T-011 in parallel
2. **Export attestation**: T-001, then T-028, then T-029
3. **Prefix matching**: T-003
4. **Plain-text word counts**: T-005..T-010 (all parallel)
5. **Plain-text revisions**: T-012, T-013 (parallel)
6. **Fingerprinting**: T-014, T-015, T-016 (parallel), then T-017
7. **Bundle monitoring**: T-018, T-019
8. **Adapters**: T-020
9. **iCloud**: T-021, then T-022
10. **Extensions**: T-023
11. **Discovery**: T-024, T-025
12. **Robustness**: T-026, T-027
13. **Paste fixes (critical)**: T-030 + T-031 + T-033 (parallel), then T-032 + T-034 + T-035 + T-039 (parallel), then T-036, then T-037 + T-038

## Priority Order

| Tier | Tasks | Rationale |
|------|-------|-----------|
| **P0** | T-030 | **BUG**: keystroke_count_after_paste never incremented; every paste scores as veneer |
| **P0** | T-039 | **BUG**: paste history lost; only last paste survives to forensic analysis |
| **P0** | T-031 | **BUG**: phantom paste from auto-save / iCloud sync / find-replace |
| **P0** | T-033 | **BUG**: 4 of 8 clipboard monitor apps have wrong bundle IDs |
| **P0** | T-000 | Eliminates 3x ZIP duplication, unblocks all format tasks |
| **P0** | T-001 | Export attestation for 104+ apps (~20 lines) |
| **P0** | T-003 | Future-proofs all versioned apps permanently |
| **P0** | T-028 | Tiered export detection: 18 formats, process-matching |
| **P1** | T-032 | Paste dedup between Rust and FFI paths (prevents counter reset) |
| **P1** | T-034 | Clipboard monitor covers all registry apps, not just 8 |
| **P1** | T-035 | FFI paste gets pasteboard type info for accurate classification |
| **P1** | T-029 | Export format + confidence annotation |
| **P1** | T-023 | ~20 new file extensions (trivial) |
| **P1** | T-004, T-005 | ODT and Fountain word count |
| **P1** | T-014 | Fountain fingerprint |
| **P1** | T-017 | Generalized fingerprint dispatch |
| **P1** | T-021 | iCloud placeholder skipping |
| **P2** | T-036 | Scale domestication threshold by paste size |
| **P2** | T-037 | Heuristic AI tool detection |
| **P2** | T-006 | LaTeX word count |
| **P2** | T-011, T-012 | ODT + Fountain revision detection |
| **P2** | T-015 | Scrivener binder structure |
| **P2** | T-018 | Vellum bundle ID fix |
| **P2** | T-020 | 5 adapters + 1 update |
| **P2** | T-024 | Probe exclusion list |
| **P3** | T-038 | Paste character volume tracking |
| **P3** | T-007..T-010 | OPML, Org, RST, AsciiDoc word counts |
| **P3** | T-013, T-016 | LaTeX revisions, OPML fingerprinting |
| **P3** | T-019 | Heuristic package detection |
| **P3** | T-022 | iCloud conflict annotation |
| **P3** | T-025 | Confidence decay |
| **P3** | T-026, T-027 | Robustness audit, probe rate limiting |

## Summary

| Phase | Tasks | What |
|-------|-------|------|
| 0 — Foundation | 3 | Fix ZIP duplication, export gating, version tolerance |
| 7 — Export Formats | 2 | Tiered export detection, format annotation |
| 1 — Word Count | 7 | ODT, Fountain, LaTeX, OPML, Org, RST, AsciiDoc |
| 2 — Revisions | 3 | ODT, Fountain, LaTeX |
| 3 — Fingerprints | 4 | Fountain, Scrivener binder, OPML, generalized dispatch |
| 4 — Bundles | 2 | Vellum fix, heuristic package detection |
| 5 — Adapters | 1 | 5 new + 1 updated (batch) |
| 6 — iCloud | 2 | Placeholder skipping, conflict detection |
| 8 — Extensions | 1 | ~20 new file extensions |
| 9 — Discovery | 2 | Exclusion list, confidence decay |
| 10 — Robustness | 2 | Format version audit, probe rate limiting |
| **11 — Paste Fixes** | **10** | **Counter bug, paste history, phantom paste, dedup, clipboard IDs, registry integration, FFI types, scaled thresholds, AI heuristic, char volume** |
| **Total** | **38** | |

**Files touched (11 unique)**:
- `crates/cpoe/src/sentinel/helpers.rs` — format intelligence, paste detection, utilities (20 tasks)
- `crates/cpoe/src/sentinel/app_registry.rs` — adapters, matching, discovery (5 tasks)
- `crates/cpoe/src/ffi/sentinel_es.rs` — export attestation (3 tasks)
- `crates/cpoe/src/ffi/text_fragment.rs` — FFI paste recording (2 tasks)
- `crates/cpoe/src/sentinel/clipboard.rs` — clipboard monitor (3 tasks)
- `crates/cpoe/src/sentinel/types.rs` — PasteContext, file extensions (2 tasks)
- `crates/cpoe/src/forensics/composition_mode.rs` — paste scoring (2 tasks)
- `crates/cpoe/src/forensics/constants.rs` — AI tool detection (1 task)
- `crates/cpoe/src/evidence/types.rs` — attestation types, paste breakdown (2 tasks)
- `crates/cpoe/src/sentinel/bundle_monitor.rs` — bundle detection (2 tasks)
- `crates/cpoe/src/sentinel/core_session.rs` — integration (3 tasks)
- `crates/cpoe/src/sentinel/mod.rs` — re-exports
- `apps/cpoe_macos/cpoe/Service/CPoESettings.swift` — macOS allowlist, FFI caller updates

**Shared utilities created by T-000 (used by 10+ tasks)**:
- `ZIP_LOCAL_HEADER_SIG` — replaces 7 inline constants
- `find_zip_entry_by_suffix(path, suffix)` — eliminates 3 independent ZIP scanning loops
- `read_xml_content(path, inner_suffix)` — single function for ZIP-or-plain XML reading
- `read_zip_entry_as_str(path, entry)` — renamed from docx-specific name

**Shared dispatcher created by T-017 (used by 3+ fingerprint functions)**:
- `structural_fingerprint(path)` — single integration point; adding a format = one match arm

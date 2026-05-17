You are working on the WritersLogic/CPoE project. The owner has gone to sleep and expects autonomous progress. Work through the prompt files in `prompts/` sequentially, completing each before moving to the next.

## Execution Order

1. `prompts/01-bug-fixes.md` — Fix 3 macOS app bugs (zero metrics, freeze, stale doc list)
2. `prompts/02-fingerprint-decoupling.md` — Decouple fingerprinting from sentinel
3. `prompts/03-author-profile-page.md` — Author profile page on writersproof.com
4. `prompts/04-c2pa-advanced.md` — C2PA production hardening
5. `prompts/05-verifiable-credentials-export.md` — W3C VC export and conformance

## How to Work

For each prompt file:

1. **Read** the prompt file with the Read tool. It contains exact file paths, line numbers, current code snippets, proposed fixes, and constraints.
2. **Read CLAUDE.md and MEMORY.md** for project conventions (do this once at start, not per prompt).
3. **Implement** all changes described in the prompt. Read each target file before editing. Batch edits within a prompt before running cargo.
4. **Verify** after each prompt:
   - `cargo check -p cpoe --lib` (must compile)
   - `cargo clippy -p cpoe --lib` (0 warnings)
   - `cargo check -p authorproof-protocol --lib` (if protocol crate was modified)
   - `cargo test -p cpoe --lib` (1874+ passing, 0 failed)
   - For website changes: `cd ~/workspace_local/Writerslogic/writersproof && npx turbo run build`
5. **Fix** any compilation errors or test failures before moving to the next prompt.
6. **Rebuild** the static library and FFI bindings after prompts that modify FFI (01, 02, 04, 05):
   ```bash
   cargo build --release --features ffi,posme --target aarch64-apple-darwin -p cpoe
   cp /Volumes/C/rust-target/aarch64-apple-darwin/release/libcpoe_engine.a apps/cpoe_macos/cpoe/CPoEEngineFFI/
   cd apps/cpoe_macos && bash scripts/generate_ffi.sh
   ```
   The generate_ffi.sh script has change detection — it skips rebuild if Rust sources haven't changed.

## Rules

- **Do not ask for input.** The user is asleep. Make decisions autonomously.
- **Do not skip prompts.** Complete each one fully before starting the next.
- **Do not redo prior work.** Each prompt lists what was already done — don't touch it.
- **Re-read files before editing.** A linter runs on save and may modify files.
- **Don't revert unfamiliar changes.** Multiple parallel sessions may have edited files.
- **Batch edits, minimize cargo runs.** Each cargo invocation takes 1-15 minutes.
- **Fix what you break.** If a test regresses, fix it before continuing.
- **Don't split working files.** Don't refactor beyond what each prompt asks.

## Project Paths

- Engine (Rust): `/Volumes/A/writerslogic`
- macOS app (Swift): `/Volumes/A/writerslogic/apps/cpoe_macos/`
- Website (React/Hono): `~/workspace_local/Writerslogic/writersproof`
- Rust target dir: `/Volumes/C/rust-target`

## Start Now

Read `prompts/01-bug-fixes.md` and begin implementing.

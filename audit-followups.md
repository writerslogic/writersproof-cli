# Audit Followups

Out-of-scope items discovered during audit. Not fixed; tracked here for future work.

---

## Batch 1 (cli.rs, cmd_attest.rs, cmd_commit.rs, cmd_config.rs, cmd_daemon.rs)

**FOLLOWUP-001** — `cmd_attest.rs`: Ephemeral session leak on checkpoint failure.
- File: `apps/cpoe_cli/src/cmd_attest.rs:53-72`
- If `ffi_ephemeral_checkpoint` fails (line 62), `ffi_start_ephemeral_session` was already called but the session is never terminated. Needs a cancel/abort FFI call if one exists.
- Action: Check FFI API for `ffi_cancel_ephemeral_session` or equivalent; add cleanup on error path.

**FOLLOWUP-002** — `cmd_daemon.rs`: `acquire_or_report` return value semantics are inverted and confusing (`Ok(true)` = "already running, stop here", `Ok(false)` = "continue").
- File: `apps/cpoe_cli/src/cmd_daemon.rs:13-40`
- Not a bug (logic is correct) but high cognitive load. Consider returning an enum or renaming.
- Action: Low priority refactor when touching daemon code.

**FOLLOWUP-003** — `cmd_daemon.rs`: `ps` + `kill` POSIX race (PID reuse between name check and signal).
- File: `apps/cpoe_cli/src/cmd_daemon.rs:180-215`
- Inherent POSIX limitation. Mitigation documented in-code (comment references H-012).
- Action: No fix possible without OS-specific APIs (pidfd on Linux, proc_info on macOS).

## Batch 2 (cmd_export/keystroke.rs, mod.rs, output.rs, packet.rs, cmd_fingerprint.rs)

**FOLLOWUP-004** — `keystroke.rs`: `eprintln!` diagnostic messages not gated by `OutputMode`; appear even in `--quiet` mode.
- File: `apps/cpoe_cli/src/cmd_export/keystroke.rs:25-116`
- Root cause: `load_keystroke_evidence` / `find_matching_session` have no access to `OutputMode`.
- Action: Add `quiet: bool` parameter to `load_keystroke_evidence` and `find_matching_session`, pass from `cmd_export`.

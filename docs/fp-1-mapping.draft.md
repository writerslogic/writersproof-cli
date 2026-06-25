# FP-1 — Frozen Fingerprint Derivation & Render Contract (DRAFT)

> **Status: DRAFT, pending lock.** This is the byte-to-parameter contract for
> fingerprint version `FP-1`, extracted verbatim from the as-built generator
> (`crates/badge-fingerprint/src/features.rs` + `fingerprint.rs` + `badge.rs`).
> Once locked, **any** change here MUST increment the version (FP-2) and MUST NOT
> retroactively alter issued records (spec §7.2, §19). Two conformant renderers
> MUST produce visually identical ridges for the same payload under FP-1.
>
> Source of truth while DRAFT: the code. On lock, this document becomes the
> source of truth and the code is conformance-tested against it.

## 0. What FP-1 covers

FP-1 has **two frozen sub-parts**; both must match across renderers:

- **Part A — `payload → FeatureVector`**: the deterministic draw sequence (this doc, §2–§4).
- **Part B — `FeatureVector → ridge geometry → SVG`**: the orientation-field model, streamline tracing, slot transform, and numeric precision (§5).

A "selected attributes" layer (tier, mode, status, ID text, issuer mark) is
explicitly **NOT** part of FP-1 (§6) — it is bound from the record and may evolve
without a version bump.

## 1. Input and digest

- **Input:** the canonical ID. As of 2026-06-24 the short-id is **9 Crockford
  Base32 payload symbols + 1 mod-37 check** (`short_id.rs`, DST `wp-short-id-v2:`),
  displayed `WP-XXX-XXX-XXX-C`; the payload is the lookup key.
  - ⚠️ **Deferred:** the fingerprint currently hashes the full short-id string
    handed to `render_badge_svg`, not the payload-only form. Switching to
    payload-only (so the check symbol / prefix can evolve without re-keying art)
    is a pending refinement.
- **Preimage (frozen literal):** the ASCII bytes of `fp-v1:` followed by the
  payload bytes. The DST literal `fp-v1:` is part of the contract — changing it
  re-keys. (Human version name is "FP-1"; the on-the-wire DST string stays
  `fp-v1:` to avoid an extra re-key.)
- **Digest:** `h = SHA-256(preimage)` → 32 bytes.

## 2. The deterministic reader (`Bits`)

A left-to-right cursor over `h`, frozen exactly as implemented:

| Op | Bytes consumed | Definition |
|----|----------------|-----------|
| `u16()` | 2 | big-endian: `(byte0 << 8) | byte1` |
| `below(n)` | 2 | `u16() % n` |
| `bit()` | 1 | `byte & 1 == 1` |
| `frac()` | 2 | `u16() * ONE / 65536`, a Q16.16 fraction in `[0,1)` |
| `range(lo,hi)` | 2 | `lo + frac()·(hi-lo)` (one `frac()`, i.e. 2 bytes) |
| **refill** | — | when the buffer is exhausted, **append `SHA-256(current_buffer)`** and continue |

`quantize(v,lo,hi,steps)` consumes **no** bytes (pure post-processing of a prior
`range`). All fixed-point math is Q16.16 (`crate::fixed`); `TURN` is the
brad full-circle constant.

## 3. Draw sequence (Part A — the variable list to lock)

Drawn in **exactly** this order. The sequence **branches on pattern class**, so
total bytes consumed vary. Struct-field evaluation order is source order
(x before y, etc.) — **reordering fields silently re-keys; do not reorder.**

| # | Parameter | Draw | Range / mapping |
|---|-----------|------|-----------------|
| 1 | `pattern` | `below(3)` | `0→Loop, 1→Whorl, 2→Arch` |
| 2 | `base_rotation` | `below(TURN)` | `(v / 64) * 64` (quantized to 64-brad steps) |
| 3 | **singular points** | *branch on pattern* | see §3.1 |
| 4 | `harmonics[0..4]` | per harmonic, 3 draws | see §3.2 (`HARMONICS = 4`) |
| 5 | `minutiae[0..7]` | per minutia, 4 draws | see §3.3 (`MINUTIAE = 7`) |
| 6 | `tooth_code[0..24]` | per tooth `below(3)` | raised ⟺ `== 0` (`TOOTH_CODE_LEN = 24`, ~1/3 raised) |
| 7 | `dot_slot` | `below(8)` | `DOT_SLOTS = 8` |
| 8 | `stars` | count `2 + below(2)`; then per star | slot `below(12)`; points `below(3)→{0:4,1:5,_:6}` |
| 9 | `fine_ridge_mask` | `(u16() << 16) | u16()` | u32, bit `i` selects ridge `i` as fine |

### 3.1 Singular points (branch)

Coordinates are normalized `0..1` of the slot.

- **Loop** (9 bytes): `core.x = range(0.42,0.58)`; `core.y = range(0.30,0.44)`;
  `left = bit()`; `delta.x = left ? range(0.22,0.36) : range(0.64,0.78)`;
  `delta.y = range(0.62,0.74)`. (one core, one delta)
- **Whorl** (6 bytes): `cx = range(0.46,0.54)`; `cy = range(0.46,0.54)`;
  `sep = range(0.06,0.11)`; deltas = `(cx, cy-sep)` and `(cx, cy+sep)`; **no core**.
- **Arch** (2 bytes): `core.x = range(0.40,0.60)`; `core.y = -0.80` (constant,
  far below slot); no delta.

### 3.2 Harmonic (×4, 6 bytes each)

- `amp = quantize(range(amp_lo, amp_hi), amp_lo, amp_hi, 6)` where
  `amp_lo = TURN/256` (≈1.4°), `amp_hi = TURN/80` (≈4.5°).
- `omega = 1 + below(3)` → integer cycles in `{1,2,3}`.
- `phase = (below(TURN) / 256) * 256` (quantized to 256-brad steps).

### 3.3 Minutia (×7, 7 bytes each)

- `kind = bit() ? Ending : Bifurcation`.
- `x = range(0.24,0.76)`; `y = range(0.24,0.76)`.
- `dir = (below(TURN) / 1024) * 1024` (quantized to 1024-brad steps).

## 4. Constants frozen by §2–§3

`TURN` (brad full circle), `ONE` (Q16.16 unit), `HARMONICS=4`, `MINUTIAE=7`,
`TOOTH_CODE_LEN=24`, `DOT_SLOTS=8`, and every numeric range/step/divisor above.

## 5. Part B — FeatureVector → ridge geometry (also frozen)

The render turns the FeatureVector into actual ridge polylines; this is equally
part of "visually identical."

- **Slot:** `SLOT = 100` user-units square; active circular region radius
  `SLOT/2 - INSET`, `INSET = 8`; center `(50,50)`.
- **Orientation field (Sherlock-Monro):**
  `θ(z) = base_rotation + 0.5·(Σ arg(z−deltaₖ) − Σ arg(z−coreₖ)) + Σ harmonics`,
  with harmonic `i`: `argᵢ = sin(omegaᵢ·zₓ·TURN + phaseᵢ)`; even `i` use that,
  odd `i` use `(sin(…zₓ…) + sin(…z_y…))/2`. `arg` via `atan2`, `0` at origin.
- **Tracing (Jobard–Lefer even-spaced streamlines):** step `1.0` unit/iter;
  `MAX_RIDGE_PTS = 110`/direction; per-step heading turn clamped to `±TURN/12`;
  ridge spacing `5` units; `MAX_RIDGES = 64`; min ridge length `6` points;
  seed lattice = center first, then a uniform grid at `spacing/2`, scanned
  row-major; even-spacing rejection via a `spacing`-wide bucket grid (3×3
  neighborhood). All deterministic.
- **Badge slot transform:** translate to disc center `(150,150)`, scale
  `SLOT_R·100 / ((SLOT/2 − INSET)·100)` with `SLOT_R = 70`, then `translate
  (−50,−50)`; clip to the **fingertip silhouette** (spec §7.3; currently a
  circle r=70 — silhouette change does not re-key, it only re-clips).
- **Stroke widths:** bold ridges `1.9`, fine ridges `1.4`; minutia ending = filled
  circle `r=0.9`; bifurcation = `4`-unit fork tine at `dir + TURN/8`, width `1`.
- **Numeric precision:** all coordinates emitted at **2 decimal places** (slot
  transform scale at 4). This rounding is part of the contract.

## 6. Selected attributes — explicitly NOT in FP-1

Bound from the record; may change with the **spec** version without an FP bump.
Rendered as concrete SVG values (not CSS custom properties in the baked artifact):

| Attribute | Source | Channels |
|-----------|--------|----------|
| Tier | record | value-ramp ink intensity + ribbon word + dot count (spec §8.2/8.3) |
| Mode | record | glyph + word (spec §8.4) |
| Status | status list | clean / revoked / suspended / expired overlay (spec §8.5) |
| ID text | payload+check | monospace text below disc |
| Issuer mark | issuer | curved banner ("WritersProof") |

## 7. Open knobs to lock before freeze

1. **ID-1 distinguisher** (separate `ID-1` contract): recommend the **content/seal
   digest** already in the record (deterministic, public, recomputable). Also pin
   *which* 80 bits of the SHA-256 and endianness.
2. **DST literal**: keep `fp-v1:` (recommended) vs rename to `FP-1:` (extra re-key).
3. **Silhouette path**: the exact fingertip clip path (does not re-key; lock for
   visual consistency).
4. Confirm **struct-field order** as a frozen hazard (a reorder re-keys silently).

---
*Extracted from commit-state of `crates/badge-fingerprint` on review; DRAFT until locked.*

#!/usr/bin/env bash
# check-stub-shadowing.sh
#
# CI-friendly tripwire for the "stub shadows extension" anti-pattern.
# Scans every Foo.swift that has at least one Foo+*.swift sibling and
# reports any function name that appears in BOTH where the base file's
# body looks like a stub (empty / TODO-only / EmptyView pass-through).
#
# Mirrors WritersLogicTests/StubShadowingDetectionTests.swift so the
# regression is caught even when running outside Xcode.
#
# Usage:
#   scripts/check-stub-shadowing.sh [path]
#
# Exits 0 if clean, 1 if offenders are found.

set -euo pipefail

ROOT="${1:-apps/cpoe_macos/cpoe}"
if [[ ! -d "$ROOT" ]]; then
    echo "error: $ROOT does not exist" >&2
    exit 2
fi

OFFENDERS=0

# For each Foo.swift in scope, find sibling Foo+*.swift files and compare.
while IFS= read -r -d '' base_file; do
    base_name="$(basename "$base_file" .swift)"
    base_dir="$(dirname "$base_file")"

    # Skip files that are themselves extensions or test files.
    if [[ "$base_name" == *"+"* ]]; then continue; fi

    # Find sibling extension files.
    shopt -s nullglob
    siblings=("$base_dir/$base_name+"*.swift)
    shopt -u nullglob
    if [[ ${#siblings[@]} -eq 0 ]]; then continue; fi

    # Extract base file's function names declared inside the type.
    # Strip line comments (// ...) before grepping so commented-out function
    # signatures inside doc/header comment blocks aren't matched as real
    # declarations.
    base_fns="$(sed -E 's|//.*$||' "$base_file" 2>/dev/null \
        | grep -Eo '\b(static\s+|private\s+|fileprivate\s+|internal\s+|public\s+|nonisolated\s+|@MainActor\s+|@ViewBuilder\s+|@discardableResult\s+|override\s+|final\s+|class\s+)*func\s+[A-Za-z][A-Za-z0-9_]*\s*[(<]' 2>/dev/null \
        | grep -oE 'func\s+[A-Za-z][A-Za-z0-9_]*' \
        | awk '{print $2}' \
        | sort -u || true)"

    [[ -z "$base_fns" ]] && continue

    # Extract function names from siblings.
    sibling_fns="$(grep -h -Eo '\b(static\s+|private\s+|fileprivate\s+|internal\s+|public\s+|nonisolated\s+|@MainActor\s+|@ViewBuilder\s+|@discardableResult\s+|override\s+|final\s+|class\s+)*func\s+[A-Za-z][A-Za-z0-9_]*\s*[(<]' "${siblings[@]}" 2>/dev/null \
        | grep -oE 'func\s+[A-Za-z][A-Za-z0-9_]*' \
        | awk '{print $2}' \
        | sort -u || true)"

    [[ -z "$sibling_fns" ]] && continue

    # Functions in both = candidates.
    candidates="$(comm -12 <(echo "$base_fns") <(echo "$sibling_fns") || true)"
    [[ -z "$candidates" ]] && continue

    # For each candidate, inspect the base file's function body.
    while IFS= read -r fn_name; do
        [[ -z "$fn_name" ]] && continue

        # Extract body using awk with proper brace-depth tracking. Walks character
        # by character, counts `{`/`}` to identify the body region between the
        # outermost matching pair. Strips strings and comments to avoid false
        # matches on `{` / `}` inside string literals or comments.
        body="$(awk -v fn="$fn_name" '
            BEGIN { inside = 0; depth = 0; in_str = 0; in_line_cmt = 0 }
            {
                line = $0
                # Drop line comments before parsing braces
                sub(/\/\/.*$/, "", line)
                if (inside == 0) {
                    # Look for `func fn_name(` or `func fn_name<` or `func fn_name `
                    if (match(line, "func[[:space:]]+" fn "[[:space:]]*[(<]")) {
                        inside = 1
                        # Trim everything before the `func` keyword
                        line = substr(line, RSTART)
                    } else next
                }
                # Now walk the (possibly trimmed) line, counting braces.
                for (i = 1; i <= length(line); i++) {
                    c = substr(line, i, 1)
                    if (c == "\"") { in_str = 1 - in_str; if (started) printf "%s", c; continue }
                    if (in_str) { if (started) printf "%s", c; continue }
                    if (c == "{") {
                        depth++
                        if (depth == 1) { started = 1; continue }
                        if (started) printf "%s", c
                    } else if (c == "}") {
                        depth--
                        if (depth == 0) { exit }
                        if (started) printf "%s", c
                    } else if (started) {
                        printf "%s", c
                    }
                }
                if (started) printf "\n"
            }
        ' "$base_file")"

        # Strip block comments, whitespace.
        stripped="$(printf '%s' "$body" \
            | sed -E 's|/\*[^*]*\*+([^/*][^*]*\*+)*/||g' \
            | tr -d '[:space:]')"

        # Detect known stub patterns. Conservative: a body counts as a stub
        # only if it's entirely empty, only the SwiftUI pass-through, or only
        # an EmptyView() return.
        is_stub=0
        if [[ -z "$stripped" ]]; then
            is_stub=1
        elif [[ "$stripped" == "Form{additionalSections()}" ]]; then
            is_stub=1
        elif [[ "$stripped" == "EmptyView()" ]]; then
            is_stub=1
        elif [[ "$stripped" == "returnEmptyView()" ]]; then
            is_stub=1
        fi

        if [[ "$is_stub" == "1" ]]; then
            echo "STUB-SHADOW: $base_file :: $fn_name (also implemented in ${siblings[0]##*/})" >&2
            OFFENDERS=$((OFFENDERS + 1))
        fi
    done <<< "$candidates"
done < <(find "$ROOT" -type f -name "*.swift" -not -path "*/Tests/*" -not -path "*/WritersLogicTests/*" -print0)

if [[ "$OFFENDERS" -gt 0 ]]; then
    echo "" >&2
    echo "Found $OFFENDERS stub-shadowing regression(s)." >&2
    echo "Each offender has an empty / TODO / pass-through body in a base file" >&2
    echo "while a sibling +Extension.swift file holds the real implementation." >&2
    echo "The stubs will silently shadow the real implementations." >&2
    echo "" >&2
    echo "Fix: remove the stubs from the base file. See the global CLAUDE.md" >&2
    echo "    'Anti-pattern: never add empty stubs to fix missing-symbol errors'" >&2
    exit 1
fi

echo "OK: no stub-shadowing regressions detected"
exit 0

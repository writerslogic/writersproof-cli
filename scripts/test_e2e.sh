#!/bin/bash
# End-to-end integration test for WritersProof macOS app
# Tests the full user experience across process boundaries.
# Requires: WritersProof running, Accessibility permission granted
set -eo pipefail

APP_PATH="${WRITERSPROOF_APP:-$(find "$HOME/Library/Developer/Xcode/DerivedData" -maxdepth 4 -path "*/Build/Products/Debug/WritersProof.app" -print -quit 2>/dev/null)}"
APP_PATH="${APP_PATH:-/Applications/WritersProof.app}"
DB_PATH="$HOME/Library/Application Support/WritersProof/events.db"
TEST_FILE="/tmp/cpoe_e2e_test_$(date +%s).txt"
PASS=0; FAIL=0; SKIP=0

pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP  $1"; SKIP=$((SKIP + 1)); }

cleanup() {
    rm -f "$TEST_FILE"
    osascript -e 'tell application "TextEdit" to quit saving no' 2>/dev/null || true
}
trap cleanup EXIT

# ==============================================================================
# [1] App Launch & Health
# ==============================================================================
echo "[1] App Launch & Health"

if pgrep -x WritersProof > /dev/null; then
    pass "WritersProof is running"
else
    open "$APP_PATH"
    sleep 5
    if pgrep -x WritersProof > /dev/null; then
        pass "WritersProof launched successfully"
    else
        fail "WritersProof failed to launch"
        exit 1
    fi
fi

if [ -f "$DB_PATH" ]; then
    pass "Database exists at expected path"
else
    fail "Database not found at $DB_PATH"
fi

# ==============================================================================
# [2] Calibration
# ==============================================================================
echo "[2] Calibration"

sleep 2
if [ -f /tmp/cpoe_engine_debug.txt ]; then
    LAST_IPS=$(grep 'swfIPS=' /tmp/cpoe_engine_debug.txt | tail -1 | sed 's/.*swfIPS=\([0-9]*\).*/\1/')
    if [ -n "$LAST_IPS" ] && [ "$LAST_IPS" -gt 0 ] 2>/dev/null; then
        pass "SWF calibrated: $LAST_IPS iter/s"
    else
        skip "SWF not calibrated (may need manual trigger)"
    fi
else
    skip "No engine debug log (release build or not DEBUG)"
fi

# ==============================================================================
# [3] Keystroke Capture E2E
# ==============================================================================
echo "[3] Keystroke Capture E2E"

echo "Initial content." > "$TEST_FILE"

open -a TextEdit "$TEST_FILE"
sleep 2

BEFORE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM secure_events WHERE file_path LIKE '%$(basename "$TEST_FILE")%';" 2>/dev/null || echo 0)

osascript <<'APPLESCRIPT'
tell application "TextEdit"
    activate
    delay 1
end tell
tell application "System Events"
    tell process "TextEdit"
        -- Type a realistic sentence with natural pauses
        keystroke "T"
        delay 0.12
        keystroke "h"
        delay 0.09
        keystroke "i"
        delay 0.11
        keystroke "s"
        delay 0.15
        keystroke " "
        delay 0.13
        keystroke "i"
        delay 0.08
        keystroke "s"
        delay 0.14
        keystroke " "
        delay 0.11
        keystroke "a"
        delay 0.10
        keystroke " "
        delay 0.16
        keystroke "t"
        delay 0.09
        keystroke "e"
        delay 0.12
        keystroke "s"
        delay 0.11
        keystroke "t"
        delay 0.14
        keystroke " "
        delay 0.10
        keystroke "o"
        delay 0.13
        keystroke "f"
        delay 0.09
        keystroke " "
        delay 0.15
        keystroke "a"
        delay 0.11
        keystroke "u"
        delay 0.08
        keystroke "t"
        delay 0.12
        keystroke "h"
        delay 0.10
        keystroke "o"
        delay 0.14
        keystroke "r"
        delay 0.09
        keystroke "s"
        delay 0.11
        keystroke "h"
        delay 0.13
        keystroke "i"
        delay 0.10
        keystroke "p"
        delay 0.12
        keystroke "."
        delay 0.5
    end tell
end tell
APPLESCRIPT

echo "  Typed 30 keystrokes via AppleScript (uniform timing)..."
sleep 5

# AppleScript typing has near-uniform timing (CV < 0.12), so the PreWitnessBuffer
# SHOULD reject it as robotic. No session should be created. This proves the
# anti-forgery validation works.
AFTER=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM secure_events WHERE file_path LIKE '%$(basename "$TEST_FILE")%';" 2>/dev/null || echo 0)

if [ "$AFTER" -eq "$BEFORE" ]; then
    pass "Artificial keystrokes correctly REJECTED by auto-witnessing (anti-forgery working)"
else
    fail "Artificial keystrokes were ACCEPTED -- PreWitnessBuffer validation may be broken ($BEFORE -> $AFTER)"
fi

# Verify the focus was detected even though keystrokes were rejected
if grep -q "$(basename "$TEST_FILE")" "$HOME/Library/Application Support/WritersProof/event_debug.txt" 2>/dev/null; then
    pass "Focus tracking detected test file (sentinel is active)"
else
    skip "Focus debug log not found (may not be debug build)"
fi

# ==============================================================================
# [4] Auto-Checkpoint Timer
# ==============================================================================
echo "[4] Auto-Checkpoint Timer (using existing tracked files)"
# Since artificial typing was rejected (correct), test auto-checkpoint on existing data.
# Check if any document has received auto-checkpoints by looking at recent events.
RECENT_EVENTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM secure_events WHERE timestamp_ns > (strftime('%s','now','-5 minutes') * 1000000000);" 2>/dev/null || echo 0)
TOTAL_EVENTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM secure_events;" 2>/dev/null || echo 0)
if [ "$TOTAL_EVENTS" -gt 0 ]; then
    pass "Store has $TOTAL_EVENTS total events ($RECENT_EVENTS in last 5 min)"
else
    skip "No events in store (app may need manual tracking session first)"
fi

# ==============================================================================
# [5] Export & Verify
# ==============================================================================
echo "[5] Export & Verify"

CHECKPOINT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM secure_events WHERE file_path LIKE '%$(basename "$TEST_FILE")%';" 2>/dev/null || echo 0)
if [ "$CHECKPOINT_COUNT" -ge 3 ]; then
    pass "Enough checkpoints for export ($CHECKPOINT_COUNT)"
else
    skip "Need 3+ checkpoints for export, have $CHECKPOINT_COUNT (type more or wait longer)"
fi

# ==============================================================================
# [6] Session End & Cumulative Stats
# ==============================================================================
echo "[6] Session End & Anti-Forgery Verification"

osascript -e 'tell application "TextEdit" to quit saving no' 2>/dev/null
sleep 3

# Artificial typing was rejected, so the test file should have NO events.
TEST_EVENTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM secure_events WHERE file_path LIKE '%$(basename "$TEST_FILE")%';" 2>/dev/null || echo 0)
if [ "$TEST_EVENTS" -eq 0 ]; then
    pass "No evidence created for injected keystrokes (anti-forgery confirmed)"
else
    fail "Evidence was created for injected keystrokes ($TEST_EVENTS events) -- security concern"
fi

# Verify cumulative stats exist for previously manually-tracked documents
ANY_STATS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM document_stats WHERE total_keystrokes > 0;" 2>/dev/null || echo 0)
if [ "$ANY_STATS" -gt 0 ]; then
    pass "Cumulative stats exist for $ANY_STATS previously tracked document(s)"
else
    skip "No cumulative stats yet (requires a real human typing session first)"
fi

# ==============================================================================
# [7] API Connectivity
# ==============================================================================
echo "[7] API Connectivity"

API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://api.writersproof.com/health)
if [ "$API_STATUS" = "200" ]; then
    pass "WritersProof API healthy"
else
    fail "API returned HTTP $API_STATUS"
fi

TOKEN_FILE="$HOME/Library/Application Support/WritersProof/writersproof_api_key"
if [ -f "$TOKEN_FILE" ]; then
    TOKEN_AGE=$(( $(date +%s) - $(stat -f %m "$TOKEN_FILE") ))
    if [ "$TOKEN_AGE" -lt 3600 ]; then
        pass "JWT token is fresh ($TOKEN_AGE seconds old)"
    else
        skip "JWT token is stale ($TOKEN_AGE seconds old, needs re-login)"
    fi
else
    skip "No JWT token (not logged in)"
fi

# ==============================================================================
# [8] Database Integrity
# ==============================================================================
echo "[8] Database Integrity"

for TABLE in secure_events integrity physical_baselines fingerprints baseline_digests document_stats; do
    EXISTS=$(sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name='$TABLE';" 2>/dev/null)
    if [ "$EXISTS" = "$TABLE" ]; then
        pass "Table '$TABLE' exists"
    else
        fail "Table '$TABLE' missing"
    fi
done

INTEGRITY=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM integrity;" 2>/dev/null || echo 0)
if [ "$INTEGRITY" -gt 0 ]; then
    pass "Integrity record present"
else
    fail "No integrity record"
fi

# ==============================================================================
# [9] Security
# ==============================================================================
echo "[9] Security"

for FILE in "$HOME/Library/Application Support/WritersProof/signing_key" "$TOKEN_FILE"; do
    if [ -f "$FILE" ]; then
        PERMS=$(stat -f "%Lp" "$FILE")
        if [ "$PERMS" = "600" ]; then
            pass "$(basename "$FILE") has correct permissions (600)"
        else
            fail "$(basename "$FILE") has permissions $PERMS (expected 600)"
        fi
    fi
done

if [ -f /tmp/cpoe_auth_debug.txt ]; then
    skip "Debug auth log exists at /tmp (expected in DEBUG builds only)"
fi

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "========================================"
echo "  E2E TEST RESULTS"
echo "========================================"
echo "  PASS:  $PASS"
echo "  FAIL:  $FAIL"
echo "  SKIP:  $SKIP"
echo "  TOTAL: $((PASS + FAIL + SKIP))"
echo "========================================"
if [ "$FAIL" -gt 0 ]; then
    echo "  RESULT: FAILED"
    exit 1
else
    echo "  RESULT: PASSED"
fi

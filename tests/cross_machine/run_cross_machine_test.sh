#!/bin/bash
# ── Cross-Machine Integration Test Runner ──
#
# Starts node A locally, SSHs into remote machine for node B,
# then runs the cross-machine integration test.
#
# Usage: bash tests/cross_machine/run_cross_machine_test.sh
#
# Prerequisites:
#   - SSH key auth to REMOTE_HOST
#   - walkie-talkie checked out at REMOTE_PATH on remote machine
#   - Rust toolchain on both machines

set -euo pipefail

# ── Configuration ──
REMOTE_HOST="${CROSS_MACHINE_HOST:-opencity@192.168.1.100}"
REMOTE_PATH="${CROSS_MACHINE_PATH:-/home/opencity/projects/walkie-talkie/core}"
LOCAL_PATH="$(cd "$(dirname "$0")/../../.." && pwd)"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Walkie Talkie — Cross-Machine Integration Test      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Local:  $LOCAL_PATH"
echo "  Remote: $REMOTE_HOST:$REMOTE_PATH"
echo ""

# ── Build on both machines ──
echo "🔨 Building locally..."
cargo build --test integration_realworld 2>&1 | tail -3

echo "🔨 Building on remote..."
ssh "$REMOTE_HOST" "cd $REMOTE_PATH && cargo build --test integration_realworld" 2>&1 | tail -3

echo ""
echo "🚀 Starting cross-machine test..."

# ── Run node A in background ──
RUST_LOG=info cargo test --test integration_realworld \
    -- cross_machine_node_a --nocapture --ignored \
    &> /tmp/wt_cross_machine_a.log &
PID_A=$!

echo "  🅰️  Node A started (PID=$PID_A)"

# ── Run node B on remote ──
echo "  🅱️  Starting Node B on remote..."
ssh "$REMOTE_HOST" "cd $REMOTE_PATH && RUST_LOG=info cargo test --test integration_realworld -- cross_machine_node_b --nocapture --ignored" \
    &> /tmp/wt_cross_machine_b.log &
PID_B=$!

# ── Wait for completion ──
echo "  ⏳ Waiting for test to complete (timeout 60s)..."
TIMEOUT=60
ELAPSED=0
while kill -0 $PID_A 2>/dev/null && kill -0 $PID_B 2>/dev/null; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "  ❌ Timeout after ${TIMEOUT}s"
        kill $PID_A 2>/dev/null || true
        kill $PID_B 2>/dev/null || true
        echo ""
        echo "  Node A log (last 10 lines):"
        tail -10 /tmp/wt_cross_machine_a.log
        echo "  Node B log (last 10 lines):"
        tail -10 /tmp/wt_cross_machine_b.log
        exit 1
    fi
done

# ── Report ──
wait $PID_A 2>/dev/null
STATUS_A=$?
wait $PID_B 2>/dev/null
STATUS_B=$?

echo ""
if [ $STATUS_A -eq 0 ] && [ $STATUS_B -eq 0 ]; then
    echo "  ✅ Cross-machine test PASSED"
else
    echo "  ❌ Cross-machine test FAILED (A=$STATUS_A, B=$STATUS_B)"
    echo ""
    echo "  Node A log (last 20 lines):"
    tail -20 /tmp/wt_cross_machine_a.log
    echo ""
    echo "  Node B log (last 20 lines):"
    tail -20 /tmp/wt_cross_machine_b.log
fi

rm -f /tmp/wt_cross_machine_a.log /tmp/wt_cross_machine_b.log

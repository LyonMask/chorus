#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# 🔬 Cross-Machine P2P Test — MBA (Node A) + Mini (Node B)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

MBA_IP="192.168.51.73"
MINI_IP="192.168.51.166"
MINI_USER="opencity"
MINI_LOG="/tmp/wt-cross-test-mini.log"
MBA_LOG="/tmp/wt-cross-test-mba.log"
DISCOVERY_TIMEOUT=15

rm -f "$MBA_LOG"

echo "╔══════════════════════════════════════════════╗"
echo "║  🔬 Cross-Machine P2P Test                  ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  MBA (Node A): $MBA_IP                   ║"
echo "║  Mini (Node B): $MINI_IP                  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

cleanup() {
    echo "🧹 Cleaning up..."
    pkill -f "p2p_basic" 2>/dev/null || true
    ssh -o ConnectTimeout=3 "$MINI_USER@$MINI_IP" "pkill -f p2p_basic" 2>/dev/null || true
    echo "✅ Done."
}
trap cleanup EXIT

# ─── Step 1: Start Node B on Mini ───────────────────
echo "📡 Step 1: Starting Node B on Mini..."
ssh "$MINI_USER@$MINI_IP" "pkill -f p2p_basic 2>/dev/null; rm -f $MINI_LOG; cd ~/projects/walkie-talkie/core && RUST_LOG=info,libp2p_mdns=debug nohup ./target/debug/examples/p2p_basic > $MINI_LOG 2>&1 & echo \$!" 
sleep 3
echo "   ✅ Node B started"

# ─── Step 2: Start Node A on MBA ────────────────────
echo "📡 Step 2: Starting Node A on MBA..."
cd ~/projects/walkie-talkie/core
pkill -f p2p_basic 2>/dev/null || true
sleep 1
RUST_LOG=info,libp2p_mdns=debug nohup ./target/debug/examples/p2p_basic > "$MBA_LOG" 2>&1 &
MBA_PID=$!
echo "   MBA PID: $MBA_PID"
sleep 2
echo "   ✅ Node A started"

# ─── Step 3: Wait for mutual mDNS discovery ─────────
echo "🔍 Step 3: Waiting for mDNS mutual discovery..."
elapsed=0
MBA_FOUND=false
MINI_FOUND=false

while [ $elapsed -lt $DISCOVERY_TIMEOUT ]; do
    if grep -q "mDNS discovered.*$MINI_IP" "$MBA_LOG" 2>/dev/null; then
        MBA_FOUND=true
    fi
    if ssh -o ConnectTimeout=2 "$MINI_USER@$MINI_IP" "grep -q 'mDNS discovered.*$MBA_IP' $MINI_LOG" 2>/dev/null; then
        MINI_FOUND=true
    fi
    
    if $MBA_FOUND && $MINI_FOUND; then
        echo "   ✅ Mutual discovery in ${elapsed}s"
        break
    fi
    
    sleep 1
    elapsed=$((elapsed + 1))
done

if ! $MBA_FOUND || ! $MINI_FOUND; then
    echo "   ⚠️  Partial/timeout after ${DISCOVERY_TIMEOUT}s"
    echo "      MBA→Mini: $($MBA_FOUND && echo '✅' || echo '❌')"
    echo "      Mini→MBA: $($MINI_FOUND && echo '✅' || echo '❌')"
fi

# Wait for connection establishment
echo "⏳ Step 4: Waiting for connection establishment (10s)..."
sleep 10

# ─── Results ─────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
echo "📊 Test Results"
echo "════════════════════════════════════════════════"

MBA_PEERS=$(grep -c "new peer" "$MBA_LOG" 2>/dev/null || echo "0")
MINI_PEERS=$(ssh -o ConnectTimeout=3 "$MINI_USER@$MINI_IP" "grep -c 'new peer' $MINI_LOG" 2>/dev/null || echo "0")
echo "  Peer events — MBA: $MBA_PEERS | Mini: $MINI_PEERS"

MBA_MESH=$(grep -c "Graft" "$MBA_LOG" 2>/dev/null || echo "0")
MINI_MESH=$(ssh -o ConnectTimeout=3 "$MINI_USER@$MINI_IP" "grep -c 'Graft' $MINI_LOG" 2>/dev/null || echo "0")
echo "  Gossipsub Graft — MBA: $MBA_MESH | Mini: $MINI_MESH"

MBA_IDENT=$(grep -c "identified" "$MBA_LOG" 2>/dev/null || echo "0")
MINI_IDENT=$(ssh -o ConnectTimeout=3 "$MINI_USER@$MINI_IP" "grep -c 'identified' $MINI_LOG" 2>/dev/null || echo "0")
echo "  Identify — MBA: $MBA_IDENT | Mini: $MINI_IDENT"

MBA_DIAL=$(grep -c "dialing" "$MBA_LOG" 2>/dev/null || echo "0")
MINI_DIAL=$(ssh -o ConnectTimeout=3 "$MINI_USER@$MINI_IP" "grep -c 'dialing' $MINI_LOG" 2>/dev/null || echo "0")
echo "  Dial attempts — MBA: $MBA_DIAL | Mini: $MINI_DIAL"

echo ""
echo "════════════════════════════════════════════════"

# Verdicts
PASS=0
TOTAL=4

if $MBA_FOUND && $MINI_FOUND; then
    echo "✅ T1 mDNS Discovery: PASS"; PASS=$((PASS+1))
elif $MBA_FOUND || $MINI_FOUND; then
    echo "⚠️  T1 mDNS Discovery: PARTIAL"
else
    echo "❌ T1 mDNS Discovery: FAIL"
fi

if [ "$MBA_PEERS" -gt 0 ] || [ "$MINI_PEERS" -gt 0 ]; then
    echo "✅ T2 Peer Connection: PASS"; PASS=$((PASS+1))
else
    echo "❌ T2 Peer Connection: FAIL"
fi

if [ "$MBA_MESH" -gt 0 ] || [ "$MINI_MESH" -gt 0 ]; then
    echo "✅ T3 Gossipsub Mesh: PASS"; PASS=$((PASS+1))
else
    echo "⚠️  T3 Gossipsub Mesh: PENDING"
fi

if [ "$MBA_IDENT" -gt 0 ] || [ "$MINI_IDENT" -gt 0 ]; then
    echo "✅ T4 Identify Protocol: PASS"; PASS=$((PASS+1))
else
    echo "⚠️  T4 Identify Protocol: PENDING"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "📊 Score: $PASS / $TOTAL"
echo ""
echo "📁 MBA Log:  $MBA_LOG"
echo "📁 Mini Log: $MINI_LOG (remote)"
echo ""
echo "💡 Nodes still alive for manual testing."

#!/usr/bin/env bash
# Validates that the Docker A/B/C/D lab is running correctly.
# Prerequisites: docker compose up --build (from examples/docker-lab/).
# Usage: bash examples/docker-lab/check-docker-lab.sh
set -euo pipefail

COORDINATOR="${PHYSARUM_COORDINATOR:-http://127.0.0.1:8080}"
PASS=0
FAIL=0

_pass() { echo "[PASS] $1"; PASS=$((PASS + 1)); }
_fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

# ── /health ──────────────────────────────────────────────────────────────────
HEALTH=$(curl -sf "$COORDINATOR/health" 2>/dev/null || true)
if echo "$HEALTH" | grep -q "ok"; then
    _pass "/health returns ok"
else
    _fail "/health did not return ok (got: $HEALTH)"
fi

# ── /agents ───────────────────────────────────────────────────────────────────
AGENTS=$(curl -sf "$COORDINATOR/agents" 2>/dev/null || true)

for agent in agent-b agent-c agent-d; do
    if echo "$AGENTS" | jq -e --arg a "$agent" '[.[].agent_id] | contains([$a])' > /dev/null 2>&1; then
        _pass "$agent is registered"
    else
        _fail "$agent not found in /agents"
    fi
done

# ── /graph ────────────────────────────────────────────────────────────────────
GRAPH=$(curl -sf "$COORDINATOR/graph" 2>/dev/null || true)

# Helper: check a single directed edge for existence, probe_success, d_ij, q_ema, sample_count.
check_edge() {
    local src="$1" tgt="$2"
    local label="edge $src -> $tgt"

    local count
    count=$(echo "$GRAPH" | jq --arg s "$src" --arg t "$tgt" \
        '[.edges[] | select(.source==$s and .target==$t)] | length' 2>/dev/null || echo "0")
    if [ "$count" -ge 1 ]; then
        _pass "$label exists"
    else
        _fail "$label not found in /graph"
        return
    fi

    local success
    success=$(echo "$GRAPH" | jq --arg s "$src" --arg t "$tgt" \
        '[.edges[] | select(.source==$s and .target==$t)] | .[0].probe_success // false' 2>/dev/null || echo "false")
    if [ "$success" = "true" ]; then
        _pass "$label probe_success=true"
    else
        _fail "$label probe_success is not true"
    fi

    local dij
    dij=$(echo "$GRAPH" | jq --arg s "$src" --arg t "$tgt" \
        '[.edges[] | select(.source==$s and .target==$t)] | .[0].d_ij // 0' 2>/dev/null || echo "0")
    if echo "$dij" | awk '{exit ($1 > 0.0) ? 0 : 1}'; then
        _pass "$label d_ij > 0.0 (got $dij)"
    else
        _fail "$label d_ij is not > 0.0 (got $dij)"
    fi

    local qema
    qema=$(echo "$GRAPH" | jq --arg s "$src" --arg t "$tgt" \
        '[.edges[] | select(.source==$s and .target==$t)] | .[0].q_ema // 0' 2>/dev/null || echo "0")
    if echo "$qema" | awk '{exit ($1 > 0.0) ? 0 : 1}'; then
        _pass "$label q_ema > 0.0 (got $qema)"
    else
        _fail "$label q_ema is not > 0.0 (got $qema)"
    fi

    local samples
    samples=$(echo "$GRAPH" | jq --arg s "$src" --arg t "$tgt" \
        '[.edges[] | select(.source==$s and .target==$t)] | .[0].sample_count // 0' 2>/dev/null || echo "0")
    if [ "$samples" -gt 0 ]; then
        _pass "$label sample_count > 0 (got $samples)"
    else
        _fail "$label sample_count is not > 0 (got $samples)"
    fi
}

# Full mesh: all six directed edges among B, C, D.
check_edge agent-b agent-c
check_edge agent-c agent-b
check_edge agent-b agent-d
check_edge agent-d agent-b
check_edge agent-c agent-d
check_edge agent-d agent-c

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

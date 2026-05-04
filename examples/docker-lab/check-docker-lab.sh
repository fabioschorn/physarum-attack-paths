#!/usr/bin/env bash
# Validates that the Docker A/B/C lab is running correctly.
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

if echo "$AGENTS" | jq -e '[.[].agent_id] | contains(["agent-b"])' > /dev/null 2>&1; then
    _pass "agent-b is registered"
else
    _fail "agent-b not found in /agents"
fi

if echo "$AGENTS" | jq -e '[.[].agent_id] | contains(["agent-c"])' > /dev/null 2>&1; then
    _pass "agent-c is registered"
else
    _fail "agent-c not found in /agents"
fi

# ── /peers/agent-b ────────────────────────────────────────────────────────────
PEERS=$(curl -sf "$COORDINATOR/peers/agent-b" 2>/dev/null || true)

if echo "$PEERS" | jq -e '[.[].agent_id] | contains(["agent-c"])' > /dev/null 2>&1; then
    _pass "/peers/agent-b contains agent-c"
else
    _fail "/peers/agent-b does not contain agent-c"
fi

if echo "$PEERS" | jq -e '[.[].agent_id] | contains(["agent-b"]) | not' > /dev/null 2>&1; then
    _pass "/peers/agent-b excludes agent-b itself"
else
    _fail "/peers/agent-b incorrectly includes agent-b"
fi

# ── /graph ────────────────────────────────────────────────────────────────────
GRAPH=$(curl -sf "$COORDINATOR/graph" 2>/dev/null || true)

EDGE_BC=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-b" and .target=="agent-c")] | length' 2>/dev/null || echo "0")
EDGE_CB=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-c" and .target=="agent-b")] | length' 2>/dev/null || echo "0")

if [ "$EDGE_BC" -ge 1 ]; then
    _pass "edge agent-b -> agent-c exists"
else
    _fail "edge agent-b -> agent-c not found in /graph"
fi

if [ "$EDGE_CB" -ge 1 ]; then
    _pass "edge agent-c -> agent-b exists"
else
    _fail "edge agent-c -> agent-b not found in /graph"
fi

BC_SUCCESS=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-b" and .target=="agent-c")] | .[0].probe_success // false' 2>/dev/null || echo "false")
CB_SUCCESS=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-c" and .target=="agent-b")] | .[0].probe_success // false' 2>/dev/null || echo "false")

if [ "$BC_SUCCESS" = "true" ]; then
    _pass "edge agent-b -> agent-c probe_success=true"
else
    _fail "edge agent-b -> agent-c probe_success is not true"
fi

if [ "$CB_SUCCESS" = "true" ]; then
    _pass "edge agent-c -> agent-b probe_success=true"
else
    _fail "edge agent-c -> agent-b probe_success is not true"
fi

BC_DIJ=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-b" and .target=="agent-c")] | .[0].d_ij // 0' 2>/dev/null || echo "0")
CB_DIJ=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-c" and .target=="agent-b")] | .[0].d_ij // 0' 2>/dev/null || echo "0")

if echo "$BC_DIJ" | awk '{exit ($1 > 0.0) ? 0 : 1}'; then
    _pass "edge agent-b -> agent-c d_ij > 0.0 (got $BC_DIJ)"
else
    _fail "edge agent-b -> agent-c d_ij is not > 0.0 (got $BC_DIJ)"
fi

if echo "$CB_DIJ" | awk '{exit ($1 > 0.0) ? 0 : 1}'; then
    _pass "edge agent-c -> agent-b d_ij > 0.0 (got $CB_DIJ)"
else
    _fail "edge agent-c -> agent-b d_ij is not > 0.0 (got $CB_DIJ)"
fi

BC_QEMA=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-b" and .target=="agent-c")] | .[0].q_ema // 0' 2>/dev/null || echo "0")
CB_QEMA=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-c" and .target=="agent-b")] | .[0].q_ema // 0' 2>/dev/null || echo "0")

if echo "$BC_QEMA" | awk '{exit ($1 > 0.0) ? 0 : 1}'; then
    _pass "edge agent-b -> agent-c q_ema > 0.0 (got $BC_QEMA)"
else
    _fail "edge agent-b -> agent-c q_ema is not > 0.0 (got $BC_QEMA)"
fi

if echo "$CB_QEMA" | awk '{exit ($1 > 0.0) ? 0 : 1}'; then
    _pass "edge agent-c -> agent-b q_ema > 0.0 (got $CB_QEMA)"
else
    _fail "edge agent-c -> agent-b q_ema is not > 0.0 (got $CB_QEMA)"
fi

BC_SAMPLES=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-b" and .target=="agent-c")] | .[0].sample_count // 0' 2>/dev/null || echo "0")
CB_SAMPLES=$(echo "$GRAPH" | jq '[.edges[] | select(.source=="agent-c" and .target=="agent-b")] | .[0].sample_count // 0' 2>/dev/null || echo "0")

if [ "$BC_SAMPLES" -gt 0 ]; then
    _pass "edge agent-b -> agent-c sample_count > 0 (got $BC_SAMPLES)"
else
    _fail "edge agent-b -> agent-c sample_count is not > 0 (got $BC_SAMPLES)"
fi

if [ "$CB_SAMPLES" -gt 0 ]; then
    _pass "edge agent-c -> agent-b sample_count > 0 (got $CB_SAMPLES)"
else
    _fail "edge agent-c -> agent-b sample_count is not > 0 (got $CB_SAMPLES)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

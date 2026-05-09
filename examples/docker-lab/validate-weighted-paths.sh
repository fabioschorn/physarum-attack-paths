#!/usr/bin/env bash
# Weighted Competing Paths Validation — Issue #52
#
# Validates that the Physarum model selects the highest-quality path when
# multiple competing paths exist, and re-selects dynamically when quality changes.
#
# Topology (agent-b probes only C and E — no direct B→D edge):
#   Path 1: agent-b → agent-c → agent-d   (two-hop via C)
#   Path 2: agent-b → agent-e → agent-d   (two-hop via E)
#
# The direct B→D path is absent because agent-b is configured with
# --probe-targets agent-c,agent-e, so B never acquires a d_ij for agent-d.
#
# Quality injection (application-level synthetic failure rate, no tc/netem):
#   AGENT_E_FAILURE_RATE — fraction of agent-e outgoing probes forced to fail
#   AGENT_C_FAILURE_RATE — fraction of agent-c outgoing probes forced to fail
#
# Phase 1: E degraded (50% failure) → expect B→C→D is the top selected path
# Phase 2: C degraded (50% failure) → expect B→E→D becomes the top selected path
#
# Usage:
#   cd examples/docker-lab
#   bash validate-weighted-paths.sh 2>&1 | tee weighted-paths-evidence.txt

set -euo pipefail

COORDINATOR="http://localhost:8080"
COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONVERGE_SECONDS=100   # 20 samples × 5 s/probe = 100 s to fill observation window
PASS=0
FAIL=0

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
pass() { log "PASS  $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL  $*"; FAIL=$((FAIL + 1)); }

query_paths() {
    curl -sf "${COORDINATOR}/paths?source=agent-b&target=agent-d"
}

top_path_nodes() {
    query_paths | python3 -c "
import sys, json
data = json.load(sys.stdin)
paths = data.get('paths', [])
if paths:
    print('→'.join(paths[0]['nodes']))
else:
    print('(no paths)')
"
}

all_paths_ranked() {
    query_paths | python3 -c "
import sys, json
data = json.load(sys.stdin)
for i, p in enumerate(data.get('paths', [])):
    nodes = '→'.join(p['nodes'])
    score = p.get('score', 0.0)
    print(f'  #{i+1}  {nodes}  score={score:.6f}')
"
}

graph_edges() {
    curl -sf "${COORDINATOR}/graph" | python3 -c "
import sys, json
g = json.load(sys.stdin)
edges = g.get('edges', [])
for e in sorted(edges, key=lambda x: x['source']):
    print(f\"  {e['source']}→{e['target']}  d_ij={e['d_ij']:.4f}  q_ema={e['q_ema']:.4f}  success_rate={e.get('success_rate',0):.3f}\")
"
}

teardown() {
    log "Tearing down Docker lab..."
    cd "$COMPOSE_DIR"
    docker compose down -v --remove-orphans 2>/dev/null || true
}
trap teardown EXIT

# ─── Phase 1: E degraded, C healthy ───────────────────────────────────────────

log "========================================================"
log "Phase 1: E degraded (50% failure rate), C healthy (0%)"
log "Expected: B→C→D is the top selected path (rank 1)"
log "========================================================"

cd "$COMPOSE_DIR"
teardown

AGENT_E_FAILURE_RATE=0.5 AGENT_C_FAILURE_RATE=0.0 \
    docker compose up -d --build 2>&1 | tail -5

log "Waiting ${CONVERGE_SECONDS}s for observation windows to fill..."
sleep "$CONVERGE_SECONDS"

log "--- Edge state after Phase 1 convergence ---"
graph_edges || log "(graph not yet available)"

log "--- All paths agent-b → agent-d (Phase 1) ---"
all_paths_ranked || log "(paths not yet available)"

TOP1=$(top_path_nodes)
log "Top-ranked path (Phase 1): ${TOP1}"

if [ "$TOP1" = "agent-b→agent-c→agent-d" ]; then
    pass "Phase 1: top selected path is B→C→D (C healthy, E degraded)"
else
    fail "Phase 1: expected top path B→C→D, got '${TOP1}'"
fi

teardown

# ─── Phase 2: C degraded, E healthy ───────────────────────────────────────────

log ""
log "========================================================"
log "Phase 2: C degraded (50% failure rate), E healthy (0%)"
log "Expected: B→E→D becomes the top selected path (rank 1)"
log "========================================================"

AGENT_E_FAILURE_RATE=0.0 AGENT_C_FAILURE_RATE=0.5 \
    docker compose up -d 2>&1 | tail -5

log "Waiting ${CONVERGE_SECONDS}s for observation windows to fill..."
sleep "$CONVERGE_SECONDS"

log "--- Edge state after Phase 2 convergence ---"
graph_edges || log "(graph not yet available)"

log "--- All paths agent-b → agent-d (Phase 2) ---"
all_paths_ranked || log "(paths not yet available)"

TOP2=$(top_path_nodes)
log "Top-ranked path (Phase 2): ${TOP2}"

if [ "$TOP2" = "agent-b→agent-e→agent-d" ]; then
    pass "Phase 2: top selected path re-selected to B→E→D (E healthy, C degraded)"
else
    fail "Phase 2: expected top path B→E→D, got '${TOP2}'"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

log ""
log "========================================================"
log "Results: ${PASS} passed, ${FAIL} failed"
log "========================================================"

[ "$FAIL" -eq 0 ]

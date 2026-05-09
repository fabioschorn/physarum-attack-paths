#!/usr/bin/env bash
# Weighted Competing Paths Validation — Issue #52
#
# Validates that the Physarum model selects the highest-quality path when
# multiple competing paths exist, and re-ranks dynamically when quality changes.
#
# Topology (full mesh — B, C, D, E all probe each other):
#   Path 1: agent-b → agent-c → agent-d   (two-hop via C)
#   Path 2: agent-b → agent-e → agent-d   (two-hop via E)
#   Path 0: agent-b → agent-d             (direct one-hop)
#
# Quality injection (application-level, no tc/netem):
#   AGENT_E_FAILURE_RATE — fraction of agent-e outgoing probes forced to fail
#   AGENT_C_FAILURE_RATE — fraction of agent-c outgoing probes forced to fail
#
# Phase 1: E degraded (50% failure) → expect B→C→D ranks above B→E→D
# Phase 2: C degraded (50% failure) → expect B→E→D re-ranks above B→C→D
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
log "Expected: B→C→D ranks above B→E→D"
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

# The direct B→D path will likely rank #1; we check that B→C→D outranks B→E→D
BCD_RANK=$(query_paths | python3 -c "
import sys, json
data = json.load(sys.stdin)
for i, p in enumerate(data.get('paths', [])):
    if p['nodes'] == ['agent-b', 'agent-c', 'agent-d']:
        print(i + 1)
        sys.exit(0)
print(99)
")
BED_RANK=$(query_paths | python3 -c "
import sys, json
data = json.load(sys.stdin)
for i, p in enumerate(data.get('paths', [])):
    if p['nodes'] == ['agent-b', 'agent-e', 'agent-d']:
        print(i + 1)
        sys.exit(0)
print(99)
")

log "B→C→D rank: ${BCD_RANK}   B→E→D rank: ${BED_RANK}"

if [ "$BCD_RANK" -lt "$BED_RANK" ]; then
    pass "Phase 1: B→C→D (rank ${BCD_RANK}) outranks B→E→D (rank ${BED_RANK})"
else
    fail "Phase 1: B→C→D (rank ${BCD_RANK}) does NOT outrank B→E→D (rank ${BED_RANK})"
fi

teardown

# ─── Phase 2: C degraded, E healthy ───────────────────────────────────────────

log ""
log "========================================================"
log "Phase 2: C degraded (50% failure rate), E healthy (0%)"
log "Expected: B→E→D re-ranks above B→C→D"
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

BCD_RANK2=$(query_paths | python3 -c "
import sys, json
data = json.load(sys.stdin)
for i, p in enumerate(data.get('paths', [])):
    if p['nodes'] == ['agent-b', 'agent-c', 'agent-d']:
        print(i + 1)
        sys.exit(0)
print(99)
")
BED_RANK2=$(query_paths | python3 -c "
import sys, json
data = json.load(sys.stdin)
for i, p in enumerate(data.get('paths', [])):
    if p['nodes'] == ['agent-b', 'agent-e', 'agent-d']:
        print(i + 1)
        sys.exit(0)
print(99)
")

log "B→C→D rank: ${BCD_RANK2}   B→E→D rank: ${BED_RANK2}"

if [ "$BED_RANK2" -lt "$BCD_RANK2" ]; then
    pass "Phase 2: B→E→D (rank ${BED_RANK2}) re-ranked above B→C→D (rank ${BCD_RANK2})"
else
    fail "Phase 2: B→E→D (rank ${BED_RANK2}) did NOT re-rank above B→C→D (rank ${BCD_RANK2})"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

log ""
log "========================================================"
log "Results: ${PASS} passed, ${FAIL} failed"
log "========================================================"

[ "$FAIL" -eq 0 ]

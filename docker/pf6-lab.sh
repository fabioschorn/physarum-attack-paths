#!/usr/bin/env bash
#
# pf6-lab.sh — physarum-maze PF-6 dual-CVE lab runner
#
# Four-container lab: three RCE targets + agent.
#   host-b (physarum-target-pf6:lab)       — Struts 2.5.25 (CVE-2020-17530, HTTP :8080) + sshd
#   host-c (physarum-target-dualcve:lab)   — ProFTPD 1.3.5 mock (CVE-2015-3306, FTP :21)
#                                            Wing FTP 7.4.3 mock (CVE-2025-47812, HTTP :80)
#                                            sshd :22 for Phase 2 delivery
#   host-d (physarum-target-ognlexec:lab)  — Apache Struts 2.5.29 (CVE-2021-31805, HTTP :8090) + sshd
#                                            OgnlExec validation: LLM must request Exploit-DB enrichment
#                                            and generate commands array autonomously
#   host-a (physarum-maze:lab)             — agent, senses the /24 subnet
#
# Phases:
#   Phase 1 (default):   LLM senses targets, identifies CVEs, TCP+HTTP probes confirm access
#   Phase 2 (opt-in):    LLM generates SSH-first exploit → pubkey injection → SCP → exec
#
# LLM mode:
#   Real LLM (auto-loaded from .env.local when present):
#     cp examples/pf-4-real-llm-lab/sensitive-info/.env.example \
#        examples/pf-4-real-llm-lab/sensitive-info/.env.local
#     # fill in PHYSARUM_LLM_ENDPOINT and LLM_API_KEY
#     ./docker/pf6-lab.sh
#
#   Explicit env vars:
#     export LLM_API_KEY="sk-..."
#     export PHYSARUM_LLM_ENDPOINT="https://api.openai.com"
#     ./docker/pf6-lab.sh
#
# Usage:
#   ./docker/pf6-lab.sh              # Phase 1 — sensing + CVE identification
#   ./docker/pf6-lab.sh --phase2     # Phase 2 — exploit enabled (requires Manager OK)
#   ./docker/pf6-lab.sh --clean      # stop containers, clear lineage
#   ./docker/pf6-lab.sh --logs       # stream last run logs

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
PASS="${GREEN}✔${NC}"; FAIL="${RED}✘${NC}"; INFO="${BLUE}→${NC}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker/docker-compose-pf6.yml"
LINEAGE_DIR="$PROJECT_ROOT/docker/lineage"

# ─── Args ─────────────────────────────────────────────────────────────────────
PHASE2="${PHYSARUM_PHASE2:-false}"
case "${1:-}" in
    --clean)
        docker compose -f "$COMPOSE_FILE" down --remove-orphans -v 2>/dev/null || true
        rm -f "$LINEAGE_DIR/physarum-lineage.json"
        echo -e "  [${PASS}] cleaned"
        exit 0
        ;;
    --logs)
        docker compose -f "$COMPOSE_FILE" logs -f host-a
        exit 0
        ;;
    --phase2)
        PHASE2="true"
        ;;
    --help|-h)
        echo "Usage: $0 [--clean | --logs | --phase2]"
        exit 0
        ;;
esac

# ─── Auto-load .env.local (credentials never appear in tool call args) ────────
ENV_LOCAL="$PROJECT_ROOT/examples/pf-4-real-llm-lab/sensitive-info/.env.local"
if [ -f "$ENV_LOCAL" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_LOCAL"
    set +a
fi

# ─── Resolve LLM config ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── LLM mode${NC}"
LLM_ENDPOINT="${PHYSARUM_LLM_ENDPOINT:-mock-http:8080}"
LLM_MODEL="${PHYSARUM_LLM_MODEL:-gpt-4o-mini}"
LLM_LOG_PROMPTS="${PHYSARUM_LLM_LOG_PROMPTS:-false}"
export PHYSARUM_LLM_ENDPOINT="$LLM_ENDPOINT"
export PHYSARUM_LLM_MODEL="$LLM_MODEL"
export PHYSARUM_LLM_LOG_PROMPTS="$LLM_LOG_PROMPTS"

if [[ "$LLM_ENDPOINT" == mock* ]]; then
    echo -e "  [${INFO}] mode:       mock (no real LLM — endpoint=$LLM_ENDPOINT)"
else
    if [ -z "${LLM_API_KEY:-}" ]; then
        echo -e "  [${FAIL}] PHYSARUM_LLM_ENDPOINT set but LLM_API_KEY is empty."
        exit 1
    fi
    echo -e "  [${PASS}] mode:       real LLM"
    echo -e "  [${INFO}] endpoint:   $LLM_ENDPOINT"
    echo -e "  [${INFO}] model:      $LLM_MODEL"
    echo -e "  [${INFO}] api_key:    present (redacted)"
fi
if [ "$LLM_LOG_PROMPTS" = "true" ]; then
    echo -e "  [${INFO}] log_prompts: ENABLED"
fi

# ─── Phase config ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Phase config${NC}"
if [ "$PHASE2" = "true" ]; then
    export PHYSARUM_EXPLOIT_ENABLED="true"
    echo -e "  [${PASS}] Phase 2 — exploit ENABLED (SSH-first binary propagation)"
    echo -e "  [${YELLOW}⚠${NC}]  REQUIRES Manager approval of Phase 1 evidence"
else
    export PHYSARUM_EXPLOIT_ENABLED="false"
    echo -e "  [${INFO}] Phase 1 — sensing + CVE identification (exploit disabled)"
fi

# ─── Prepare lineage dir ──────────────────────────────────────────────────────
mkdir -p "$LINEAGE_DIR"
rm -f "$LINEAGE_DIR/physarum-lineage.json"

# ─── Start lab ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Starting PF-6 dual-CVE lab${NC}"
echo -e "  [${INFO}] host-b: physarum-target-pf6:lab      172.21.0.3  :8080 Struts/CVE-2020-17530  :22 sshd"
echo -e "  [${INFO}] host-c: physarum-target-dualcve:lab 172.21.0.4  :21 ProFTPD/CVE-2015-3306   :80 WingFTP/CVE-2025-47812  :22 sshd"
echo -e "  [${INFO}] host-d: physarum-target-ognlexec:lab 172.21.0.5  :8090 Struts/CVE-2021-31805 (OgnlExec)  :22 sshd"
echo -e "  [${INFO}] host-a: physarum-maze:lab            172.21.0.2  agent"
echo ""

trap 'on_exit' INT TERM EXIT

on_exit() {
    echo ""
    echo -e "${BOLD}── Lab stopped — lineage evidence:${NC}"
    LINEAGE_FILE="$LINEAGE_DIR/physarum-lineage.json"
    if [ -f "$LINEAGE_FILE" ]; then
        python3 - "$LINEAGE_FILE" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    lin = json.load(f)
attempts = lin.get("llm_attempts", [])
print(f"  Hops:  {lin.get('hops', 0)}")
print(f"  Path:  {' → '.join(lin.get('path', []))}")
print(f"  LLM attempts: {len(attempts)}")
for a in attempts:
    decision = a.get("policy_decision", {})
    status = "ACCEPTED" if decision == "Accepted" else "REJECTED"
    result = a.get("execution_result", {})
    outcome = "✔ Success" if result == "Success" else f"✘ {result}"
    enriched = " [enriched]" if a.get("enrichment_requested") else ""
    ref_id = a.get("exploit_reference_id", "")
    ref_str = f"  ref={ref_id}" if ref_id else ""
    print(f"\n  Attempt {a['attempt_number']}:  policy={status}  result={outcome}{enriched}{ref_str}")
    print(f"    cve_candidates: {a.get('cve_candidate_ids', [])}")
    print(f"    summary: {a.get('reasoning_summary', '')}")
PYEOF
        echo ""
        echo -e "  Full lineage: $LINEAGE_FILE"
    else
        echo -e "  [${YELLOW}⚠${NC}] No lineage file — host-a may not have produced evidence yet"
    fi
    docker compose -f "$COMPOSE_FILE" down --remove-orphans -v 2>/dev/null || true
}

docker compose -f "$COMPOSE_FILE" up -d --remove-orphans --pull=never
docker compose -f "$COMPOSE_FILE" logs -f host-a

#!/usr/bin/env bash
#
# docker-lab.sh — physarum-llm Docker Lab runner (Issue #106 Phase 5)
#
# What this script does:
#   1. Compiles physarum-maze locally (cargo build --release)
#   2. Builds the Docker image via Docker Cloud (cloud-expertsonline-physarum-attack-paths)
#   3. Creates the lineage output directory
#   4. Starts the two-container lab (docker compose up)
#   5. Streams host-a logs in real time
#   6. On exit (Ctrl-C or timeout) prints the lineage evidence
#
# Usage:
#   ./Utilities/docker-lab.sh            # run the lab
#   ./Utilities/docker-lab.sh --clean    # remove containers and lineage output
#   ./Utilities/docker-lab.sh --logs     # show logs of last run without rebuilding

set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
PASS="${GREEN}✔${NC}"; FAIL="${RED}✘${NC}"; INFO="${BLUE}→${NC}"

# ─── Config ───────────────────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"
COMPOSE_FILE="$DOCKER_DIR/docker-compose-lab.yml"
DOCKERFILE="$DOCKER_DIR/physarum-maze.Dockerfile"
LINEAGE_DIR="$DOCKER_DIR/lineage"
IMAGE_TAG="physarum-maze:lab"
CLOUD_BUILDER="cloud-expertsonline-physarum-attack-paths"

# ─── Argument handling ────────────────────────────────────────────────────────
case "${1:-}" in
    --clean)
        echo -e "${INFO} Stopping containers and removing lineage output..."
        docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
        rm -rf "$LINEAGE_DIR"
        echo -e "  [${PASS}] cleaned"
        exit 0
        ;;
    --logs)
        echo -e "${INFO} Streaming last run logs..."
        docker compose -f "$COMPOSE_FILE" logs -f host-a
        exit 0
        ;;
    --help|-h)
        echo "Usage: $0 [--clean | --logs]"
        exit 0
        ;;
esac

# ─── Step 1: Compile physarum-maze locally ─────────────────────────────────
echo ""
echo -e "${BOLD}── Step 1: cargo build --release${NC}"
cargo build --release -p physarum-maze \
    --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1 | tail -3
echo -e "  [${PASS}] physarum-maze compiled"

# ─── Step 2: Build Docker image via Docker Cloud ───────────────────────────
echo ""
echo -e "${BOLD}── Step 2: docker buildx build (cloud builder)${NC}"
echo -e "  [${INFO}] builder: $CLOUD_BUILDER"

docker buildx build \
    --builder "$CLOUD_BUILDER" \
    --platform linux/amd64 \
    --load \
    -t "$IMAGE_TAG" \
    -f "$DOCKERFILE" \
    "$PROJECT_ROOT"

echo -e "  [${PASS}] image built: $IMAGE_TAG"

# ─── Step 3: Prepare lineage output directory ──────────────────────────────
mkdir -p "$LINEAGE_DIR"
echo -e "  [${PASS}] lineage dir: $LINEAGE_DIR"

# ─── Step 4: Start lab ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Step 3: docker compose up${NC}"
echo -e "  [${INFO}] host-b: nginx:alpine (172.20.0.3, port 80 only)"
echo -e "  [${INFO}] host-a: physarum-maze (172.20.0.2, --llm-endpoint mock-http)"
echo -e "  [${INFO}] Press Ctrl-C to stop and view lineage evidence"
echo ""

# Run compose in background so we can trap exit
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans

# Stream host-a logs — this is where the reasoning loop output appears
trap 'on_exit' INT TERM EXIT

on_exit() {
    echo ""
    echo -e "${BOLD}── Lab stopped — lineage evidence:${NC}"
    LINEAGE_FILE="$LINEAGE_DIR/physarum-lineage.json"
    if [ -f "$LINEAGE_FILE" ]; then
        echo ""
        # Summary: number of LLM attempts and their outcomes
        python3 - "$LINEAGE_FILE" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    lin = json.load(f)

attempts = lin.get("llm_attempts", [])
print(f"  Hops:          {lin.get('hops', 0)}")
print(f"  Path:          {' → '.join(lin.get('path', []))}")
print(f"  LLM attempts:  {len(attempts)}")

for a in attempts:
    decision = a.get("policy_decision", {})
    status   = "ACCEPTED" if decision == "Accepted" else f"REJECTED({decision.get('Rejected', {}).get('reason', '?')})"
    result   = a.get("execution_result", {})
    if result == "Success":
        outcome = "✔ Success"
    elif isinstance(result, dict):
        outcome = f"✘ {list(result.keys())[0]}"
    else:
        outcome = str(result)

    print(f"\n  Attempt {a['attempt_number']}:")
    print(f"    method:  {a['method_class']}")
    print(f"    policy:  {status}")
    print(f"    result:  {outcome}")
    print(f"    summary: {a['reasoning_summary']}")
PYEOF
        echo ""
        echo -e "  Full lineage: $LINEAGE_FILE"
    else
        echo -e "  [${YELLOW}⚠${NC}] No lineage file found — host-a may not have run yet"
    fi
    docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
}

docker compose -f "$COMPOSE_FILE" logs -f host-a

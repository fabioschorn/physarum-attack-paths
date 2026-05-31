#!/usr/bin/env bash
#
# docker-lab.sh — physarum-maze Docker Lab runner (PF-3.1 / PF-4)
#
# Four-container lab validating the adaptive sensing + LLM reasoning pipeline:
#   host-a (physarum-maze:lab)        — agent, senses the /24 subnet
#   host-b (nginx:alpine :80)         — ConfirmedWeb via service_guess="http"
#   host-c (python http.server :8080) — ConfirmedWeb via service_guess="http-alt"
#   host-d (python http.server :7777) — UnknownNeedsMoreSensing → ConfirmedWeb
#                                       via Layer 3 targeted HTTP probe
#
# LLM mode (controlled by host environment variables):
#
#   PF-3.1 mock (default, no API key):
#     ./Utilities/docker-lab.sh
#
#   PF-4 real LLM (OpenAI-compatible):
#     export LLM_API_KEY="sk-..."
#     export PHYSARUM_LLM_ENDPOINT="https://api.openai.com"
#     export PHYSARUM_LLM_MODEL="gpt-4o-mini"      # optional, default gpt-4o-mini
#     ./Utilities/docker-lab.sh
#
#   PF-4 with local Ollama (Mac host):
#     export LLM_API_KEY="ollama"
#     export PHYSARUM_LLM_ENDPOINT="http://host.docker.internal:11434"
#     export PHYSARUM_LLM_MODEL="llama3.2"
#     ./Utilities/docker-lab.sh
#
# What this script does:
#   1. Verifies local Rust toolchain is >= 1.86
#   2. Builds the Docker image via Docker Cloud (cloud-expertsonline-physarum-attack-paths)
#      using OCI export + docker load (cloud builder cannot --load directly)
#   3. Creates the lineage output directory
#   4. Starts the four-container lab (docker compose up)
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
DOCKERFILE="$DOCKER_DIR/physarum-maze-lab.Dockerfile"
LINEAGE_DIR="$DOCKER_DIR/lineage"
IMAGE_TAG="physarum-maze:lab"
OCI_TAR="/tmp/physarum-maze-lab.tar"
CLOUD_BUILDER="cloud-expertsonline-physarum-attack-paths"
MIN_RUST_VERSION="1.86.0"

# ─── Helpers ──────────────────────────────────────────────────────────────────
version_ge() {
    # Returns true when $1 >= $2 for dotted numeric versions such as 1.86.0.
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

check_rust_toolchain() {
    if ! command -v rustc >/dev/null 2>&1; then
        echo -e "  [${FAIL}] rustc not found. Install Rust ${MIN_RUST_VERSION} via rustup."
        exit 1
    fi

    local version
    version="$(rustc --version | awk '{print $2}')"

    if ! version_ge "$version" "$MIN_RUST_VERSION"; then
        echo -e "  [${FAIL}] Rust ${MIN_RUST_VERSION}+ required; found ${version}."
        echo -e "        Run: rustup toolchain install ${MIN_RUST_VERSION}"
        echo -e "        The repository also pins this via rust-toolchain.toml."
        exit 1
    fi

    echo -e "  [${PASS}] rustc ${version}"
}

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

# ─── Step 0a: Verify Rust toolchain ───────────────────────────────────────────
echo ""
echo -e "${BOLD}── Step 0a: verify Rust toolchain${NC}"
check_rust_toolchain

# ─── Step 0b: Detect LLM mode ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Step 0b: LLM mode${NC}"
LLM_ENDPOINT="${PHYSARUM_LLM_ENDPOINT:-mock-http}"
LLM_MODEL="${PHYSARUM_LLM_MODEL:-gpt-4o-mini}"

if [ "$LLM_ENDPOINT" = "mock-http" ]; then
    echo -e "  [${INFO}] mode:     PF-3.1 mock (no real LLM — HTTP GET against host-b:80)"
    echo -e "  [${INFO}] To run PF-4 real LLM:"
    echo -e "           export LLM_API_KEY=\"sk-...\""
    echo -e "           export PHYSARUM_LLM_ENDPOINT=\"https://api.openai.com\""
    echo -e "           export PHYSARUM_LLM_MODEL=\"gpt-4o-mini\""
else
    if [ -z "${LLM_API_KEY:-}" ]; then
        echo -e "  [${FAIL}] PHYSARUM_LLM_ENDPOINT is set but LLM_API_KEY is empty."
        echo -e "        Set LLM_API_KEY before running in real-LLM mode."
        exit 1
    fi
    echo -e "  [${PASS}] mode:     PF-4 real LLM"
    echo -e "  [${INFO}] endpoint: $LLM_ENDPOINT"
    echo -e "  [${INFO}] model:    $LLM_MODEL"
    echo -e "  [${INFO}] api_key:  ${LLM_API_KEY:0:8}... (masked)"
fi

# ─── Step 1: Build Docker image via Docker Cloud ───────────────────────────
# Cloud builder cannot --load directly; export OCI tar then docker load.
echo ""
echo -e "${BOLD}── Step 1: docker buildx build (cloud builder)${NC}"
echo -e "  [${INFO}] builder:  $CLOUD_BUILDER"
echo -e "  [${INFO}] output:   $OCI_TAR"

docker buildx build \
    --builder "$CLOUD_BUILDER" \
    --platform linux/amd64 \
    --output "type=oci,dest=$OCI_TAR" \
    -t "$IMAGE_TAG" \
    -f "$DOCKERFILE" \
    "$PROJECT_ROOT"

echo -e "  [${INFO}] loading image into docker daemon..."
docker load -i "$OCI_TAR"
echo -e "  [${PASS}] image loaded: $IMAGE_TAG"

# ─── Step 2: Prepare lineage output directory ──────────────────────────────
mkdir -p "$LINEAGE_DIR"
echo -e "  [${PASS}] lineage dir: $LINEAGE_DIR"

# ─── Step 3: Start lab ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Step 3: docker compose up${NC}"
echo -e "  [${INFO}] host-b: nginx:alpine        172.20.0.3 :80   (ConfirmedWeb via service_guess)"
echo -e "  [${INFO}] host-c: python http.server  172.20.0.4 :8080 (ConfirmedWeb via service_guess)"
echo -e "  [${INFO}] host-d: python http.server  172.20.0.5 :7777 (Layer 3 HTTP probe)"
echo -e "  [${INFO}] host-a: physarum-maze        172.20.0.2       (agent, --llm-endpoint mock-http)"
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

#!/usr/bin/env bash
#
# build.sh — Compila o workspace e executa todos os testes automaticamente.
#
# Uso:
#   ./Utilities/build.sh                # build debug + testes
#   ./Utilities/build.sh --release      # build release (otimizado) + testes
#   ./Utilities/build.sh --check        # só verifica se compila, sem gerar binários
#   ./Utilities/build.sh --no-test      # compila sem rodar os testes
#   ./Utilities/build.sh --clippy       # inclui análise estática (clippy)

set -euo pipefail

# ─── Cores e símbolos ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

PASS="${GREEN}✔${NC}"
FAIL="${RED}✘${NC}"
WARN="${YELLOW}⚠${NC}"
INFO="${BLUE}→${NC}"

# ─── Argumentos ──────────────────────────────────────────────────────────────
MODE="debug"
RUN_TESTS=true
CHECK_ONLY=false
RUN_CLIPPY=false

for arg in "$@"; do
    case "$arg" in
        --release)  MODE="release" ;;
        --check)    CHECK_ONLY=true ;;
        --no-test)  RUN_TESTS=false ;;
        --clippy)   RUN_CLIPPY=true ;;
        --help|-h)
            echo "Uso: $0 [--release] [--check] [--no-test] [--clippy]"
            echo ""
            echo "  --release   Compila em modo release (otimizado, mais lento)"
            echo "  --check     Apenas verifica se o código compila, sem gerar binários"
            echo "  --no-test   Pula a etapa de testes"
            echo "  --clippy    Executa análise estática com clippy após o build"
            exit 0
            ;;
        *)
            echo -e "${RED}Argumento desconhecido: $arg${NC}"
            echo "Use --help para ver as opções disponíveis."
            exit 1
            ;;
    esac
done

# ─── Configuração ─────────────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$PROJECT_ROOT/Cargo.toml"

overall_start=$(date +%s)
step_errors=0

# ─── Funções auxiliares ───────────────────────────────────────────────────────
section() {
    echo ""
    echo -e "${BOLD}── $1${NC}"
}

pass()   { echo -e "  [${PASS}] $1"; }
fail()   { echo -e "  [${FAIL}] ${RED}$1${NC}"; ((step_errors+=1)); }
warn()   { echo -e "  [${WARN}] ${YELLOW}$1${NC}"; }
info()   { echo -e "  [${INFO}] ${BLUE}$1${NC}"; }

elapsed() {
    local start=$1
    local end
    end=$(date +%s)
    echo $(( end - start ))s
}

run_step() {
    local label="$1"
    shift
    local step_start
    step_start=$(date +%s)

    echo ""
    echo -e "  ${BOLD}Executando:${NC} $*"
    echo ""

    if "$@" 2>&1 | sed 's/^/    /'; then
        local took
        took=$(elapsed "$step_start")
        pass "$label concluído em ${took}"
        return 0
    else
        local took
        took=$(elapsed "$step_start")
        fail "$label falhou após ${took}"
        return 1
    fi
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║        Physarum Attack Paths — Build & Test          ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
info "Projeto   : $PROJECT_ROOT"
info "Modo      : $MODE"
info "Testes    : $([ "$RUN_TESTS" = true ] && echo 'sim' || echo 'não')"
info "Clippy    : $([ "$RUN_CLIPPY" = true ] && echo 'sim' || echo 'não')"
info "Iniciado  : $(date '+%Y-%m-%d %H:%M:%S')"

# ─── Pré-requisitos ───────────────────────────────────────────────────────────
section "Pré-requisitos"

if ! command -v cargo &>/dev/null; then
    fail "cargo não encontrado. Execute ./Utilities/check-env.sh para diagnosticar."
    exit 1
fi
pass "cargo $(cargo --version | awk '{print $2}') encontrado"

if [[ ! -f "$MANIFEST" ]]; then
    fail "Cargo.toml não encontrado em $PROJECT_ROOT"
    exit 1
fi
pass "Cargo.toml (workspace) encontrado"

# ─── Etapa 1: cargo check ou cargo build ─────────────────────────────────────
section "Etapa 1 — $([ "$CHECK_ONLY" = true ] && echo 'Verificação de compilação (cargo check)' || echo "Build ($MODE)")"

if [ "$CHECK_ONLY" = true ]; then
    if ! run_step "cargo check" \
            cargo check \
            --manifest-path "$MANIFEST" \
            --workspace \
            --all-targets; then
        ((step_errors+=1))
    fi
else
    BUILD_ARGS=(
        cargo build
        --manifest-path "$MANIFEST"
        --workspace
    )
    [ "$MODE" = "release" ] && BUILD_ARGS+=(--release)

    if ! run_step "cargo build ($MODE)" "${BUILD_ARGS[@]}"; then
        ((step_errors+=1))
    fi
fi

# ─── Etapa 2: clippy (opcional) ───────────────────────────────────────────────
if [ "$RUN_CLIPPY" = true ]; then
    section "Etapa 2 — Análise estática (cargo clippy)"

    CLIPPY_ARGS=(
        cargo clippy
        --manifest-path "$MANIFEST"
        --workspace
        --all-targets
        --
        -D warnings
    )

    if ! run_step "cargo clippy" "${CLIPPY_ARGS[@]}"; then
        ((step_errors+=1))
    fi
fi

# ─── Etapa 3: testes ──────────────────────────────────────────────────────────
if [ "$RUN_TESTS" = true ]; then
    STEP_NUM=$([ "$RUN_CLIPPY" = true ] && echo 3 || echo 2)
    section "Etapa $STEP_NUM — Testes (cargo test)"

    TEST_ARGS=(
        cargo test
        --manifest-path "$MANIFEST"
        --workspace
    )
    [ "$MODE" = "release" ] && TEST_ARGS+=(--release)

    if ! run_step "cargo test" "${TEST_ARGS[@]}"; then
        ((step_errors+=1))
    fi
fi

# ─── Resumo de binários gerados ───────────────────────────────────────────────
if [ "$CHECK_ONLY" = false ] && [ "$step_errors" -eq 0 ]; then
    section "Binários gerados"

    TARGET_DIR="$PROJECT_ROOT/target/$MODE"
    if [[ -d "$TARGET_DIR" ]]; then
        # Lista apenas binários do projeto (não deps)
        BINS=$(find "$TARGET_DIR" -maxdepth 1 -type f -perm +111 \
               ! -name "*.d" ! -name "*.rlib" ! -name "*.rmeta" \
               ! -name "build" ! -name "deps" ! -name "examples" \
               2>/dev/null | sort)

        if [[ -n "$BINS" ]]; then
            while IFS= read -r bin; do
                SIZE=$(du -sh "$bin" 2>/dev/null | awk '{print $1}')
                pass "$(basename "$bin")  ($SIZE)  → $bin"
            done <<< "$BINS"
        else
            info "Nenhum binário encontrado em $TARGET_DIR"
        fi
    fi
fi

# ─── Resumo final ─────────────────────────────────────────────────────────────
total_time=$(elapsed "$overall_start")

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                      Resumo                         ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${NC}"

if [[ $step_errors -eq 0 ]]; then
    echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ Build concluído com sucesso em ${total_time}.${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ "$CHECK_ONLY" = false ]; then
        echo -e "${BOLD}Como executar o servidor:${NC}"
        echo ""
        echo "  cargo run -p physarum-server -- --listen 127.0.0.1:8080"
        echo ""
        echo -e "${BOLD}Como testar os endpoints (em outro terminal):${NC}"
        echo ""
        echo "  # Health check"
        echo "  curl http://127.0.0.1:8080/health"
        echo ""
        echo "  # Registrar um agente"
        echo '  curl -s -X POST http://127.0.0.1:8080/register \'
        echo '    -H "Content-Type: application/json" \'
        echo '    -d '"'"'{"agent_id":"agent-b","address":"127.0.0.1","probe_port":9001}'"'"
        echo ""
        echo "  # Listar agentes registrados"
        echo "  curl http://127.0.0.1:8080/agents"
        echo ""
    fi
else
    echo -e "${BOLD}${BLUE}║${NC}  ${RED}✘ $step_errors etapa(s) falharam. Corrija os erros acima.${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Dica:${NC} Execute ./Utilities/check-env.sh para verificar o ambiente."
    echo ""
fi

exit $step_errors

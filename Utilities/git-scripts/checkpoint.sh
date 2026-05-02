#!/usr/bin/env bash
#
# checkpoint.sh — Salva o progresso do projeto com bump de versão minor.
#                 Faz commit + push SEM criar tag (não dispara GitHub Actions).
#
# Uso:
#   ./Utilities/git-scripts/checkpoint.sh           # bump minor: 0.0.1 → 0.1.0
#   ./Utilities/git-scripts/checkpoint.sh --patch   # bump patch: 0.0.1 → 0.0.2
#   ./Utilities/git-scripts/checkpoint.sh --no-push # commit local, sem push
#
# Diferença para release.sh:
#   checkpoint.sh → bump + commit + push (sem tag, sem binários publicados)
#   release.sh    → bump + commit + tag + push (dispara GitHub Actions)

set -euo pipefail

# ─── Cores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS="${GREEN}✔${NC}"
FAIL="${RED}✘${NC}"
WARN="${YELLOW}⚠${NC}"
INFO="${BLUE}→${NC}"

# ─── Argumentos ──────────────────────────────────────────────────────────────
BUMP_MODE="minor"
NO_PUSH=false

for arg in "$@"; do
    case "$arg" in
        --patch)   BUMP_MODE="patch" ;;
        --minor)   BUMP_MODE="minor" ;;
        --no-push) NO_PUSH=true ;;
        --help|-h)
            echo "Uso: $0 [--patch | --minor] [--no-push]"
            echo ""
            echo "  --patch     Bump patch:  0.0.1 → 0.0.2  (padrão: minor)"
            echo "  --minor     Bump minor:  0.0.1 → 0.1.0"
            echo "  --no-push   Apenas commit local, sem push para origin"
            echo ""
            echo "  Sem argumentos: bump minor + commit + push (sem tag)"
            exit 0
            ;;
        *) echo -e "${RED}Argumento desconhecido: $arg${NC}"; exit 1 ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_TOML="$PROJECT_ROOT/Cargo.toml"

# ─── Funções ──────────────────────────────────────────────────────────────────
pass()  { echo -e "  [${PASS}] $1"; }
fail()  { echo -e "  [${FAIL}] ${RED}$1${NC}"; }
warn()  { echo -e "  [${WARN}] ${YELLOW}$1${NC}"; }
info()  { echo -e "  [${INFO}] ${BLUE}$1${NC}"; }

abort() {
    echo ""
    echo -e "  ${RED}Checkpoint cancelado.${NC}"
    echo ""
    exit 1
}

get_current_version() {
    grep '^version' "$CARGO_TOML" | head -1 | sed 's/version *= *"\(.*\)"/\1/'
}

bump_version() {
    local version="$1" bump="$2"
    local major minor patch
    IFS='.' read -r major minor patch <<< "$version"
    case "$bump" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "${major}.$((minor + 1)).0" ;;
        patch) echo "${major}.${minor}.$((patch + 1))" ;;
    esac
}

update_cargo_version() {
    local new_version="$1"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        sed -i '' "0,/^version *= *\"[^\"]*\"/s//version       = \"${new_version}\"/" "$CARGO_TOML"
    else
        sed -i "0,/^version *= *\"[^\"]*\"/s//version       = \"${new_version}\"/" "$CARGO_TOML"
    fi
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║     Physarum Attack Paths — Checkpoint de Progresso  ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

cd "$PROJECT_ROOT"

# ─── Etapa 1: Validações ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 1 — Validações${NC}"
echo ""

command -v git &>/dev/null || { fail "git não encontrado."; exit 1; }
pass "git disponível"

git rev-parse --git-dir &>/dev/null || { fail "Não é um repositório git."; exit 1; }

BRANCH=$(git rev-parse --abbrev-ref HEAD)
pass "Branch: ${CYAN}${BRANCH}${NC}"

# Working tree limpa?
if git diff --quiet && git diff --cached --quiet; then
    if [[ -z "$(git ls-files --others --exclude-standard)" ]]; then
        warn "Nenhuma alteração encontrada. Nada para salvar."
        exit 0
    fi
fi
pass "Alterações detectadas"

# Remote configurado?
if $NO_PUSH; then
    info "Modo --no-push: push desabilitado"
elif git remote get-url origin &>/dev/null; then
    REMOTE_URL=$(git remote get-url origin)
    pass "Remote: ${CYAN}${REMOTE_URL}${NC}"
else
    warn "Nenhum remote 'origin' configurado. Usando --no-push automaticamente."
    NO_PUSH=true
fi

# ─── Etapa 2: Versão ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 2 — Versão${NC}"
echo ""

CURRENT_VERSION=$(get_current_version)
NEW_VERSION=$(bump_version "$CURRENT_VERSION" "$BUMP_MODE")

info "Versão atual: ${CYAN}${CURRENT_VERSION}${NC}"
info "Nova versão:  ${GREEN}${NEW_VERSION}${NC}  (bump ${BUMP_MODE})"

# ─── Etapa 3: Cargo check ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 3 — Validação de compilação${NC}"
echo ""
echo -e "  Executando cargo check..."
echo ""

if cargo check --workspace --manifest-path "$CARGO_TOML" --quiet 2>&1 | sed 's/^/    /'; then
    pass "cargo check OK"
else
    fail "Erros de compilação detectados. Corrija antes de criar um checkpoint."
    abort
fi

# ─── Etapa 4: Alterações que serão salvas ────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 4 — Alterações detectadas${NC}"
echo ""
git status --short | sed 's/^/    /'

# ─── Etapa 5: Confirmação ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 5 — Confirmação${NC}"
echo ""
echo -e "  O seguinte será executado:"
echo ""
echo -e "    ${CYAN}1.${NC} Bump de versão: ${YELLOW}${CURRENT_VERSION}${NC} → ${GREEN}${NEW_VERSION}${NC}"
echo -e "    ${CYAN}2.${NC} git add -A (todos os arquivos alterados)"
echo -e "    ${CYAN}3.${NC} Commit: ${GREEN}chore: checkpoint v${NEW_VERSION}${NC}"
if $NO_PUSH; then
    echo -e "    ${CYAN}4.${NC} ${YELLOW}Push desabilitado (--no-push)${NC}"
else
    echo -e "    ${CYAN}4.${NC} Push para ${CYAN}origin/${BRANCH}${NC} ${YELLOW}(sem tag — sem GitHub Actions)${NC}"
fi
echo ""
echo -e "  ${BOLD}Confirmar? [S/n]${NC} \c"
read -r CONFIRM

[[ "$CONFIRM" =~ ^[nN]$ ]] && abort

# ─── Etapa 6: Execução ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 6 — Salvando checkpoint${NC}"
echo ""

update_cargo_version "$NEW_VERSION"
pass "Cargo.toml atualizado → ${GREEN}${NEW_VERSION}${NC}"

git add -A
pass "Arquivos adicionados ao staging"

git commit -m "chore: checkpoint v${NEW_VERSION}"
COMMIT_HASH=$(git rev-parse --short HEAD)
pass "Commit criado: ${CYAN}${COMMIT_HASH}${NC}"

if ! $NO_PUSH; then
    git push origin "$BRANCH"
    pass "Push realizado para ${CYAN}origin/${BRANCH}${NC}"
fi

# ─── Resumo ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                  Checkpoint Salvo!                   ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ v${NEW_VERSION} — commit ${COMMIT_HASH}${NC}"
if $NO_PUSH; then
    echo -e "${BOLD}${BLUE}║${NC}  ${YELLOW}⚠ Push não realizado (--no-push)${NC}"
fi
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Próximos passos:${NC}"
echo ""
if $NO_PUSH; then
    echo "  Enviar para o GitHub:"
    echo "    git push origin $BRANCH"
    echo ""
fi
echo "  Continuar desenvolvendo e fazer outro checkpoint:"
echo "    ./Utilities/git-scripts/checkpoint.sh"
echo ""
echo "  Quando pronto para release oficial:"
echo "    ./Utilities/git-scripts/release.sh --minor"
echo ""

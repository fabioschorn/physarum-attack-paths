#!/usr/bin/env bash
#
# release.sh — Automatiza o fluxo completo de release:
#              bump de versão → commit → tag → push → GitHub Actions publica.
#
# Uso:
#   ./Utilities/git-scripts/release.sh             # modo interativo
#   ./Utilities/git-scripts/release.sh --patch     # bump automático: 0.0.1 → 0.0.2
#   ./Utilities/git-scripts/release.sh --minor     # bump automático: 0.0.1 → 0.1.0
#   ./Utilities/git-scripts/release.sh --major     # bump automático: 0.0.1 → 1.0.0
#
# O que este script faz:
#   1. Valida o ambiente (branch main, working tree limpa, testes OK)
#   2. Mostra a versão atual e calcula a próxima
#   3. Atualiza a versão no Cargo.toml do workspace
#   4. Cria um commit: "chore: release v0.2.0"
#   5. Cria a tag: v0.2.0
#   6. Faz push do commit e da tag
#   7. O GitHub Actions (release.yml) detecta a tag e publica os binários

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
BUMP_MODE=""
for arg in "$@"; do
    case "$arg" in
        --patch) BUMP_MODE="patch" ;;
        --minor) BUMP_MODE="minor" ;;
        --major) BUMP_MODE="major" ;;
        --help|-h)
            echo "Uso: $0 [--patch | --minor | --major]"
            echo ""
            echo "  --patch   Incrementa a versão patch:  0.0.1 → 0.0.2"
            echo "  --minor   Incrementa a versão minor:  0.0.1 → 0.1.0"
            echo "  --major   Incrementa a versão major:  0.0.1 → 1.0.0"
            echo ""
            echo "  Sem argumentos: modo interativo com menu."
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
    echo -e "  ${RED}Release cancelada.${NC}"
    echo ""
    exit 1
}

# Lê a versão atual do Cargo.toml do workspace
get_current_version() {
    grep '^version' "$CARGO_TOML" | head -1 | sed 's/version *= *"\(.*\)"/\1/'
}

# Calcula a próxima versão dado o tipo de bump
bump_version() {
    local version="$1"
    local bump="$2"
    local major minor patch

    IFS='.' read -r major minor patch <<< "$version"

    case "$bump" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "${major}.$((minor + 1)).0" ;;
        patch) echo "${major}.${minor}.$((patch + 1))" ;;
    esac
}

# Atualiza a versão no Cargo.toml (apenas na seção [workspace.package])
update_cargo_version() {
    local new_version="$1"
    # Substitui apenas a primeira ocorrência de version = "x.y.z"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        sed -i '' "0,/^version *= *\"[^\"]*\"/s//version       = \"${new_version}\"/" "$CARGO_TOML"
    else
        sed -i "0,/^version *= *\"[^\"]*\"/s//version       = \"${new_version}\"/" "$CARGO_TOML"
    fi
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║       Physarum Attack Paths — Release Manager        ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

cd "$PROJECT_ROOT"

# ─── Etapa 1: Validações ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 1 — Validações${NC}"
echo ""

# git disponível?
command -v git &>/dev/null || { fail "git não encontrado."; exit 1; }
pass "git disponível"

# É um repositório git?
git rev-parse --git-dir &>/dev/null || { fail "Não é um repositório git."; exit 1; }

# Branch atual
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" != "main" && "$BRANCH" != "master" ]]; then
    warn "Você está na branch '${CYAN}${BRANCH}${NC}${YELLOW}', não em 'main'."
    echo ""
    echo -e "  Releases devem ser feitas a partir de 'main'. Deseja continuar mesmo assim? [s/N] \c"
    read -r BRANCH_ANSWER
    [[ "$BRANCH_ANSWER" =~ ^[sS]$ ]] || abort
else
    pass "Branch: ${CYAN}${BRANCH}${NC}"
fi

# Working tree limpa?
if ! git diff --quiet || ! git diff --cached --quiet; then
    fail "Working tree com alterações não commitadas."
    echo ""
    git status --short | sed 's/^/    /'
    echo ""
    echo -e "  ${YELLOW}Commit ou descarte as alterações antes de fazer uma release.${NC}"
    echo -e "  ${YELLOW}Use: ./Utilities/git-scripts/commit.sh${NC}"
    abort
fi
pass "Working tree limpa"

# Remote configurado?
if git remote get-url origin &>/dev/null; then
    REMOTE_URL=$(git remote get-url origin)
    pass "Remote: ${CYAN}${REMOTE_URL}${NC}"
else
    warn "Nenhum remote 'origin' configurado. O push não será possível."
fi

# ─── Etapa 2: Versão ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 2 — Versão${NC}"
echo ""

CURRENT_VERSION=$(get_current_version)
info "Versão atual no Cargo.toml: ${CYAN}${CURRENT_VERSION}${NC}"

# Última tag git
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "nenhuma")
info "Última tag git:             ${CYAN}${LAST_TAG}${NC}"

# Calcula sugestões
NEXT_PATCH=$(bump_version "$CURRENT_VERSION" patch)
NEXT_MINOR=$(bump_version "$CURRENT_VERSION" minor)
NEXT_MAJOR=$(bump_version "$CURRENT_VERSION" major)

if [[ -n "$BUMP_MODE" ]]; then
    NEW_VERSION=$(bump_version "$CURRENT_VERSION" "$BUMP_MODE")
    info "Nova versão (--${BUMP_MODE}):        ${GREEN}${NEW_VERSION}${NC}"
else
    echo ""
    echo -e "  Qual versão deseja publicar?"
    echo ""
    echo -e "    ${CYAN}1${NC}  patch   ${CURRENT_VERSION} → ${GREEN}${NEXT_PATCH}${NC}   (bug fixes)"
    echo -e "    ${CYAN}2${NC}  minor   ${CURRENT_VERSION} → ${GREEN}${NEXT_MINOR}${NC}   (nova funcionalidade, sem breaking change)"
    echo -e "    ${CYAN}3${NC}  major   ${CURRENT_VERSION} → ${GREEN}${NEXT_MAJOR}${NC}   (breaking change)"
    echo -e "    ${CYAN}4${NC}  manual  digitar a versão manualmente"
    echo ""
    echo -e "  ${BOLD}Escolha [1-4]:${NC} \c"
    read -r VERSION_CHOICE

    case "$VERSION_CHOICE" in
        1) NEW_VERSION="$NEXT_PATCH" ;;
        2) NEW_VERSION="$NEXT_MINOR" ;;
        3) NEW_VERSION="$NEXT_MAJOR" ;;
        4)
            echo -e "  ${BOLD}Nova versão (ex: 0.2.0):${NC} \c"
            read -r MANUAL_VERSION
            MANUAL_VERSION=$(echo "$MANUAL_VERSION" | xargs | sed 's/^v//')
            if ! [[ "$MANUAL_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                fail "Formato inválido. Use: MAJOR.MINOR.PATCH (ex: 0.2.0)"
                abort
            fi
            NEW_VERSION="$MANUAL_VERSION"
            ;;
        *) fail "Opção inválida."; abort ;;
    esac
fi

TAG_NAME="v${NEW_VERSION}"

# Verifica se a tag já existe
if git tag -l | grep -q "^${TAG_NAME}$"; then
    fail "A tag ${TAG_NAME} já existe."
    abort
fi

# ─── Etapa 3: Testes ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 3 — Testes antes da release${NC}"
echo ""
echo -e "  Executando cargo test..."
echo ""

if cargo test --workspace --manifest-path "$CARGO_TOML" --quiet 2>&1 | sed 's/^/    /'; then
    pass "Todos os testes passaram"
else
    fail "Testes falharam. Release cancelada."
    abort
fi

# ─── Etapa 4: Confirmação ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 4 — Confirmação${NC}"
echo ""
echo -e "  O seguinte será executado:"
echo ""
echo -e "    ${CYAN}1.${NC} Atualizar Cargo.toml: ${YELLOW}${CURRENT_VERSION}${NC} → ${GREEN}${NEW_VERSION}${NC}"
echo -e "    ${CYAN}2.${NC} Commit: ${GREEN}chore: release ${TAG_NAME}${NC}"
echo -e "    ${CYAN}3.${NC} Tag:    ${GREEN}${TAG_NAME}${NC}"
echo -e "    ${CYAN}4.${NC} Push do commit + tag para ${CYAN}origin/${BRANCH}${NC}"
echo -e "    ${CYAN}5.${NC} GitHub Actions irá:"
echo -e "       → compilar para ${CYAN}5 plataformas${NC}"
echo -e "       → publicar em ${CYAN}GitHub Releases${NC}"
echo ""
echo -e "  ${BOLD}${RED}Esta ação não pode ser desfeita facilmente. Confirmar? [s/N]${NC} \c"
read -r FINAL_CONFIRM

[[ "$FINAL_CONFIRM" =~ ^[sS]$ ]] || abort

# ─── Etapa 5: Execução ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 5 — Executando release${NC}"
echo ""

# Atualiza versão no Cargo.toml
update_cargo_version "$NEW_VERSION"
pass "Cargo.toml atualizado → versão ${GREEN}${NEW_VERSION}${NC}"

# Commit do bump de versão
git add "$CARGO_TOML"
git commit -m "chore: release ${TAG_NAME}"
COMMIT_HASH=$(git rev-parse --short HEAD)
pass "Commit criado: ${CYAN}${COMMIT_HASH}${NC}"

# Cria a tag anotada
git tag -a "$TAG_NAME" -m "Release ${TAG_NAME}"
pass "Tag criada: ${CYAN}${TAG_NAME}${NC}"

# Push do commit
git push origin "$BRANCH"
pass "Branch '${BRANCH}' enviada para origin"

# Push da tag (dispara o GitHub Actions)
git push origin "$TAG_NAME"
pass "Tag '${TAG_NAME}' enviada para origin — ${GREEN}GitHub Actions iniciado${NC}"

# ─── Resumo ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                   Release Iniciada!                  ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ ${TAG_NAME} enviada com sucesso.${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Acompanhe o progresso em:${NC}"
echo ""
REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")
if [[ -n "$REMOTE_URL" ]]; then
    # Converte SSH para HTTPS para exibição
    REPO_URL=$(echo "$REMOTE_URL" \
        | sed 's|git@github.com:|https://github.com/|' \
        | sed 's|\.git$||')
    echo "  GitHub Actions : ${CYAN}${REPO_URL}/actions${NC}"
    echo "  Releases       : ${CYAN}${REPO_URL}/releases/tag/${TAG_NAME}${NC}"
fi
echo ""
echo -e "  Os binários estarão disponíveis em ${CYAN}~10 minutos${NC}."
echo ""

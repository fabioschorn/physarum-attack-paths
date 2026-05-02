#!/usr/bin/env bash
#
# commit.sh — Automatiza commits seguindo o padrão Conventional Commits.
#             https://www.conventionalcommits.org
#
# Uso:
#   ./Utilities/git-scripts/commit.sh
#   ./Utilities/git-scripts/commit.sh --no-verify   # pula fmt/test
#
# Formato gerado:
#   feat(agent): adiciona loop de probe com RTT
#   fix: corrige panic no registro duplicado
#   chore(ci): atualiza matrix de targets no release.yml

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
SKIP_VERIFY=false
for arg in "$@"; do
    case "$arg" in
        --no-verify) SKIP_VERIFY=true ;;
        --help|-h)
            echo "Uso: $0 [--no-verify]"
            echo ""
            echo "  --no-verify   Pula verificações de fmt e testes antes do commit"
            exit 0
            ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ─── Funções ──────────────────────────────────────────────────────────────────
pass()  { echo -e "  [${PASS}] $1"; }
fail()  { echo -e "  [${FAIL}] ${RED}$1${NC}"; }
warn()  { echo -e "  [${WARN}] ${YELLOW}$1${NC}"; }
info()  { echo -e "  [${INFO}] ${BLUE}$1${NC}"; }

abort() {
    echo ""
    echo -e "  ${RED}Abortado.${NC}"
    exit 1
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║        Physarum Attack Paths — Git Commit            ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

cd "$PROJECT_ROOT"

# ─── Verificações iniciais ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Verificações${NC}"
echo ""

# Git instalado?
if ! command -v git &>/dev/null; then
    fail "git não encontrado."
    exit 1
fi
pass "git disponível"

# É um repositório git?
if ! git rev-parse --git-dir &>/dev/null; then
    fail "Não é um repositório git: $PROJECT_ROOT"
    exit 1
fi

# Branch atual
BRANCH=$(git rev-parse --abbrev-ref HEAD)
pass "Branch atual: ${CYAN}${BRANCH}${NC}"

# Há algo para commitar?
if git diff --quiet && git diff --cached --quiet; then
    # Verifica arquivos untracked também
    if [[ -z "$(git ls-files --others --exclude-standard)" ]]; then
        warn "Nenhuma alteração encontrada. Nada para commitar."
        exit 0
    fi
fi

# ─── Status atual ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Alterações detectadas${NC}"
echo ""
git status --short | sed 's/^/    /'

# ─── Verificações de qualidade (cargo fmt + test) ────────────────────────────
if [ "$SKIP_VERIFY" = false ] && command -v cargo &>/dev/null; then
    echo ""
    echo -e "${BOLD}── Verificações de qualidade${NC}"
    echo ""

    echo -e "  Verificando formatação (cargo fmt)..."
    if cargo fmt --all --manifest-path "$PROJECT_ROOT/Cargo.toml" -- --check &>/dev/null 2>&1; then
        pass "Formatação OK"
    else
        warn "Código fora do padrão de formatação."
        echo ""
        echo -e "  ${YELLOW}Deseja corrigir automaticamente com 'cargo fmt'? [s/N]${NC} \c"
        read -r FMT_ANSWER
        if [[ "$FMT_ANSWER" =~ ^[sS]$ ]]; then
            cargo fmt --all --manifest-path "$PROJECT_ROOT/Cargo.toml"
            pass "Formatação corrigida"
        else
            warn "Continuando sem corrigir a formatação."
        fi
    fi

    echo -e "  Executando testes (cargo test)..."
    if cargo test --workspace --manifest-path "$PROJECT_ROOT/Cargo.toml" --quiet 2>&1 | tail -3 | sed 's/^/    /'; then
        pass "Testes OK"
    else
        echo ""
        fail "Testes falharam."
        echo ""
        echo -e "  ${YELLOW}Deseja commitar mesmo assim? [s/N]${NC} \c"
        read -r TEST_ANSWER
        [[ "$TEST_ANSWER" =~ ^[sS]$ ]] || abort
    fi
fi

# ─── Modo arquivo ou interativo ───────────────────────────────────────────────
COMMIT_MSG_FILE="$PROJECT_ROOT/tmp/commit-msg.txt"
BODY_MSG=""

if [[ -f "$COMMIT_MSG_FILE" ]]; then
    # ── Modo arquivo: mensagem pré-definida em tmp/commit-msg.txt ────────────
    COMMIT_HEADER=$(head -1 "$COMMIT_MSG_FILE")

    echo ""
    echo -e "${BOLD}── Mensagem pré-definida ${CYAN}(tmp/commit-msg.txt)${NC}"
    echo ""
    sed 's/^/    /' "$COMMIT_MSG_FILE"
    echo ""
else
    # ── Modo interativo: fluxo Conventional Commits ───────────────────────────
    echo ""
    echo -e "${BOLD}── Tipo do commit ${BLUE}(Conventional Commits)${NC}"
    echo ""
    echo -e "    ${CYAN}1${NC}  feat      Nova funcionalidade"
    echo -e "    ${CYAN}2${NC}  fix       Correção de bug"
    echo -e "    ${CYAN}3${NC}  docs      Apenas documentação"
    echo -e "    ${CYAN}4${NC}  refactor  Refatoração (sem nova funcionalidade, sem bug fix)"
    echo -e "    ${CYAN}5${NC}  test      Adição ou correção de testes"
    echo -e "    ${CYAN}6${NC}  chore     Build, CI/CD, dependências, configuração"
    echo -e "    ${CYAN}7${NC}  perf      Melhoria de performance"
    echo -e "    ${CYAN}8${NC}  style     Formatação, ponto-e-vírgula (sem mudança de lógica)"
    echo ""
    echo -e "  ${BOLD}Tipo [1-8]:${NC} \c"
    read -r TYPE_CHOICE

    case "$TYPE_CHOICE" in
        1) COMMIT_TYPE="feat" ;;
        2) COMMIT_TYPE="fix" ;;
        3) COMMIT_TYPE="docs" ;;
        4) COMMIT_TYPE="refactor" ;;
        5) COMMIT_TYPE="test" ;;
        6) COMMIT_TYPE="chore" ;;
        7) COMMIT_TYPE="perf" ;;
        8) COMMIT_TYPE="style" ;;
        *) fail "Opção inválida: $TYPE_CHOICE"; abort ;;
    esac

    echo ""
    echo -e "  ${BOLD}Escopo (opcional — ex: agent, server, protocol, ci):${NC} \c"
    read -r SCOPE_INPUT
    SCOPE_INPUT=$(echo "$SCOPE_INPUT" | xargs)

    if [[ -n "$SCOPE_INPUT" ]]; then
        SCOPE="($SCOPE_INPUT)"
    else
        SCOPE=""
    fi

    echo ""
    echo -e "  ${BOLD}Descrição curta (em minúsculas, sem ponto final):${NC}"
    echo -e "  ${BLUE}→${NC} \c"
    read -r SHORT_MSG

    SHORT_MSG=$(echo "$SHORT_MSG" | xargs)
    if [[ -z "$SHORT_MSG" ]]; then
        fail "A descrição não pode ser vazia."
        abort
    fi
    SHORT_MSG="${SHORT_MSG%.}"

    echo ""
    echo -e "  ${BOLD}Corpo / detalhes (opcional — Enter para pular):${NC}"
    echo -e "  ${BLUE}→${NC} \c"
    read -r BODY_MSG
    BODY_MSG=$(echo "$BODY_MSG" | xargs)

    COMMIT_HEADER="${COMMIT_TYPE}${SCOPE}: ${SHORT_MSG}"

    echo ""
    echo -e "${BOLD}── Preview do commit${NC}"
    echo ""
    echo -e "    ${GREEN}${COMMIT_HEADER}${NC}"
    [[ -n "$BODY_MSG" ]] && echo -e "    ${NC}${BODY_MSG}"
    echo ""
fi

# ─── Staging ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}── Staging${NC}"
echo ""
echo -e "  Deseja adicionar TODOS os arquivos alterados? [S/n] \c"
read -r STAGE_ALL

if [[ "$STAGE_ALL" =~ ^[nN]$ ]]; then
    echo ""
    echo -e "  ${YELLOW}Abra outro terminal e use 'git add <arquivo>' para escolher os arquivos.${NC}"
    echo -e "  Pressione Enter quando estiver pronto... \c"
    read -r
else
    git add -A
    pass "Todos os arquivos adicionados ao staging"
fi

# Verifica se há algo staged
if git diff --cached --quiet; then
    warn "Nenhum arquivo no staging. Commit cancelado."
    abort
fi

echo ""
echo -e "${BOLD}── Arquivos que serão commitados${NC}"
echo ""
git diff --cached --name-status | sed 's/^/    /'

# ─── Confirmação final ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Confirmar commit? [S/n]${NC} \c"
read -r CONFIRM

[[ "$CONFIRM" =~ ^[nN]$ ]] && abort

# ─── Commit ───────────────────────────────────────────────────────────────────
if [[ -f "$COMMIT_MSG_FILE" ]]; then
    git commit -F "$COMMIT_MSG_FILE"
    rm -f "$COMMIT_MSG_FILE"
    info "Arquivo temporário removido: tmp/commit-msg.txt"
elif [[ -n "$BODY_MSG" ]]; then
    git commit -m "$COMMIT_HEADER" -m "$BODY_MSG"
else
    git commit -m "$COMMIT_HEADER"
fi

echo ""
COMMIT_HASH=$(git rev-parse --short HEAD)
pass "Commit criado: ${CYAN}${COMMIT_HASH}${NC} — ${GREEN}${COMMIT_HEADER}${NC}"

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                      Resumo                         ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ Commit $COMMIT_HASH realizado com sucesso.${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Próximos passos:${NC}"
echo ""
echo "  Enviar para o GitHub:"
echo "    git push origin $BRANCH"
echo ""
echo "  Criar uma release:"
echo "    ./Utilities/git-scripts/release.sh"
echo ""

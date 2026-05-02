#!/usr/bin/env bash
#
# issues.sh — Lista Issues abertos no GitHub para orientar o trabalho do engenheiro.
#             Usa o GitHub CLI (gh) para buscar e exibir os issues formatados.
#
# Uso:
#   ./Utilities/git-scripts/issues.sh
#   ./Utilities/git-scripts/issues.sh --label "bug"
#   ./Utilities/git-scripts/issues.sh --label "enhancement"
#   ./Utilities/git-scripts/issues.sh --assignee "@me"
#   ./Utilities/git-scripts/issues.sh --limit 10
#   ./Utilities/git-scripts/issues.sh --detail <número>

set -euo pipefail

# ─── Cores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

PASS="${GREEN}✔${NC}"
FAIL="${RED}✘${NC}"
WARN="${YELLOW}⚠${NC}"
INFO="${BLUE}→${NC}"

# ─── Argumentos ──────────────────────────────────────────────────────────────
FILTER_LABEL=""
FILTER_ASSIGNEE=""
LIMIT=50
DETAIL_NUMBER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --label)
            FILTER_LABEL="$2"
            shift 2
            ;;
        --assignee)
            FILTER_ASSIGNEE="$2"
            shift 2
            ;;
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        --detail)
            DETAIL_NUMBER="$2"
            shift 2
            ;;
        --help|-h)
            echo ""
            echo -e "${BOLD}Uso:${NC} $0 [FLAGS]"
            echo ""
            echo "  Sem flags         Lista todos os Issues abertos"
            echo "  --label <label>   Filtra por label (ex: bug, enhancement)"
            echo "  --assignee <user> Filtra por responsável (use @me para si mesmo)"
            echo "  --limit <n>       Limita o número de Issues exibidos (padrão: 50)"
            echo "  --detail <n>      Exibe detalhes completos do Issue número <n>"
            echo "  --help            Exibe esta ajuda"
            echo ""
            exit 0
            ;;
        *)
            echo -e "  ${RED}Flag desconhecida: $1${NC}"
            echo "  Use --help para ver as opções disponíveis."
            exit 1
            ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

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

# Formata data ISO para um formato legível: "2025-01-15T10:30:00Z" → "15 Jan 2025"
format_date() {
    local iso_date="$1"
    if command -v date &>/dev/null; then
        date -j -f "%Y-%m-%dT%H:%M:%SZ" "$iso_date" "+%d %b %Y" 2>/dev/null \
            || echo "$iso_date" | cut -c1-10
    else
        echo "$iso_date" | cut -c1-10
    fi
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║      Physarum Attack Paths — GitHub Issues           ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

# ─── Verificações iniciais ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Verificações${NC}"
echo ""

if ! command -v gh &>/dev/null; then
    fail "GitHub CLI (gh) não encontrado."
    echo ""
    echo -e "  Instale com:"
    echo -e "    ${CYAN}brew install gh${NC}          (macOS)"
    echo -e "    ${CYAN}sudo apt install gh${NC}      (Ubuntu/Debian)"
    echo -e "  Depois autentique-se com: ${CYAN}gh auth login${NC}"
    echo ""
    exit 1
fi
pass "GitHub CLI (gh) disponível: $(gh --version | head -1)"

if ! gh auth status &>/dev/null 2>&1; then
    fail "Não autenticado no GitHub CLI."
    echo ""
    echo -e "  Execute: ${CYAN}gh auth login${NC}"
    echo ""
    exit 1
fi
pass "Autenticado no GitHub"

# Detecta o repositório a partir do remote origin
if ! git remote get-url origin &>/dev/null 2>&1; then
    fail "Remote 'origin' não configurado."
    echo ""
    echo -e "  Configure com: ${CYAN}git remote add origin <url>${NC}"
    echo ""
    exit 1
fi

REPO_URL=$(git remote get-url origin)
# Extrai owner/repo de URLs SSH (git@github.com:owner/repo.git) ou HTTPS
REPO=$(echo "$REPO_URL" \
    | sed -E 's|git@github\.com:||' \
    | sed -E 's|https://github\.com/||' \
    | sed -E 's|\.git$||')

pass "Repositório: ${CYAN}${REPO}${NC}"

# ─── Modo detalhe: exibe um Issue específico ─────────────────────────────────
if [[ -n "$DETAIL_NUMBER" ]]; then
    echo ""
    echo -e "${BOLD}── Issue #${DETAIL_NUMBER}${NC}"
    echo ""
    gh issue view "$DETAIL_NUMBER" --repo "$REPO"
    echo ""
    exit 0
fi

# ─── Busca Issues abertos ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Buscando Issues abertos${NC}"
echo ""

# Monta os filtros adicionais
GH_ARGS=()
[[ -n "$FILTER_LABEL" ]]    && GH_ARGS+=("--label" "$FILTER_LABEL")
[[ -n "$FILTER_ASSIGNEE" ]] && GH_ARGS+=("--assignee" "$FILTER_ASSIGNEE")

# Busca em JSON para formatação customizada
ISSUES_JSON=$(gh issue list \
    --repo "$REPO" \
    --state open \
    --limit "$LIMIT" \
    --json number,title,labels,assignees,createdAt,url,body \
    "${GH_ARGS[@]}" 2>/dev/null)

TOTAL=$(echo "$ISSUES_JSON" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [[ "$TOTAL" == "0" ]]; then
    echo -e "  ${GREEN}Nenhum Issue aberto encontrado.${NC}"
    [[ -n "$FILTER_LABEL" ]]    && echo -e "  ${DIM}Filtro label: ${FILTER_LABEL}${NC}"
    [[ -n "$FILTER_ASSIGNEE" ]] && echo -e "  ${DIM}Filtro assignee: ${FILTER_ASSIGNEE}${NC}"
    echo ""
    exit 0
fi

# ─── Cabeçalho da tabela ─────────────────────────────────────────────────────
echo ""
if [[ -n "$FILTER_LABEL" ]];    then echo -e "  ${DIM}Filtro: label = ${YELLOW}${FILTER_LABEL}${NC}"; fi
if [[ -n "$FILTER_ASSIGNEE" ]]; then echo -e "  ${DIM}Filtro: assignee = ${CYAN}${FILTER_ASSIGNEE}${NC}"; fi

echo ""
printf "  ${BOLD}%-6s  %-52s  %-18s  %-12s${NC}\n" "Issue" "Título" "Labels" "Aberto em"
printf "  %s\n" "$(printf '─%.0s' {1..92})"

# ─── Exibe cada Issue ─────────────────────────────────────────────────────────
echo "$ISSUES_JSON" | python3 - <<'PYEOF'
import json, sys, os

data = json.load(sys.stdin)

CYAN    = '\033[0;36m'
YELLOW  = '\033[1;33m'
GREEN   = '\033[0;32m'
MAGENTA = '\033[0;35m'
DIM     = '\033[2m'
BOLD    = '\033[1m'
NC      = '\033[0m'

# Mapeia labels para cores
LABEL_COLORS = {
    'bug':         '\033[0;31m',   # vermelho
    'enhancement': '\033[0;32m',   # verde
    'feature':     '\033[0;32m',   # verde
    'documentation':'\033[0;34m',  # azul
    'docs':        '\033[0;34m',   # azul
    'question':    '\033[0;35m',   # magenta
    'help wanted': '\033[1;33m',   # amarelo
    'good first issue': '\033[1;32m',  # verde brilhante
    'wontfix':     '\033[2m',      # dim
    'duplicate':   '\033[2m',      # dim
    'invalid':     '\033[2m',      # dim
}

def label_color(name):
    return LABEL_COLORS.get(name.lower(), '\033[0;36m')  # cyan por padrão

def fmt_date(iso):
    return iso[:10] if iso else '—'

for issue in data:
    num    = f"#{issue['number']}"
    title  = issue['title'][:51]
    date   = fmt_date(issue.get('createdAt', ''))

    raw_labels = [l['name'] for l in issue.get('labels', [])]
    if raw_labels:
        colored = ', '.join(
            f"{label_color(l)}{l}{NC}" for l in raw_labels[:2]
        )
        label_str = colored
        label_display = ', '.join(raw_labels[:2])
        # Padding: label_str tem escapes ANSI, precisamos ajustar
        pad = 18 - min(len(label_display), 18)
    else:
        label_str = f"{DIM}—{NC}"
        pad = 17

    print(f"  {CYAN}{num:<6}{NC}  {title:<52}  {label_str}{' ' * max(0, pad)}  {DIM}{date}{NC}")

PYEOF

# ─── Rodapé ───────────────────────────────────────────────────────────────────
echo ""
printf "  %s\n" "$(printf '─%.0s' {1..92})"
echo ""
echo -e "  ${BOLD}${TOTAL} Issue(s) aberto(s)${NC}"
echo ""
echo -e "  ${DIM}Para ver detalhes de um Issue:${NC}"
echo -e "    ${CYAN}./Utilities/git-scripts/issues.sh --detail <número>${NC}"
echo ""
echo -e "  ${DIM}Para criar um novo Issue:${NC}"
echo -e "    ${CYAN}gh issue create --repo ${REPO}${NC}"
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                      Concluído                      ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

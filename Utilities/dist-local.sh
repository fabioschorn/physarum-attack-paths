#!/usr/bin/env bash
#
# dist-local.sh — Gera um pacote distribuível localmente para testes.
#                 Simula o que o GitHub Actions faz no release.yml,
#                 mas apenas para a plataforma atual (macOS/Linux).
#
# Uso:
#   ./Utilities/dist-local.sh
#   ./Utilities/dist-local.sh --version v0.1.0
#
# Saída:
#   dist/physarum-server-<version>-<target>.tar.gz

set -euo pipefail

# ─── Cores ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

PASS="${GREEN}✔${NC}"
FAIL="${RED}✘${NC}"
INFO="${BLUE}→${NC}"

# ─── Configuração ─────────────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_NAME="physarum-server"
DIST_DIR="$PROJECT_ROOT/dist"

# Detecta a versão: argumento --version, tag git, ou fallback
VERSION="dev"
for arg in "$@"; do
    case "$arg" in
        --version) shift; VERSION="$1"; shift ;;
    esac
done

if [[ "$VERSION" == "dev" ]]; then
    GIT_TAG=$(git -C "$PROJECT_ROOT" describe --tags --exact-match 2>/dev/null || echo "")
    if [[ -n "$GIT_TAG" ]]; then
        VERSION="$GIT_TAG"
    fi
fi

# Detecta o target Rust da plataforma atual
detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os-$arch" in
        Darwin-arm64)  echo "aarch64-apple-darwin" ;;
        Darwin-x86_64) echo "x86_64-apple-darwin" ;;
        Linux-x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        Linux-aarch64) echo "aarch64-unknown-linux-gnu" ;;
        *)
            echo ""
            ;;
    esac
}

TARGET="$(detect_target)"

if [[ -z "$TARGET" ]]; then
    echo -e "  [${FAIL}] ${RED}Plataforma não suportada: $(uname -s)-$(uname -m)${NC}"
    exit 1
fi

ASSET_NAME="${BINARY_NAME}-${VERSION}-${TARGET}"
ARCHIVE="${DIST_DIR}/${ASSET_NAME}.tar.gz"

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║    Physarum Attack Paths — Packaging Local           ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  [${INFO}] ${BLUE}Versão  : $VERSION${NC}"
echo -e "  [${INFO}] ${BLUE}Target  : $TARGET${NC}"
echo -e "  [${INFO}] ${BLUE}Saída   : $ARCHIVE${NC}"

# ─── Build release ────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 1 — Build release${NC}"
echo ""
echo -e "  Executando: cargo build --release -p $BINARY_NAME"
echo ""

cargo build --release --manifest-path "$PROJECT_ROOT/Cargo.toml" -p "$BINARY_NAME" 2>&1 | sed 's/^/    /'

BINARY_PATH="$PROJECT_ROOT/target/release/$BINARY_NAME"
if [[ ! -f "$BINARY_PATH" ]]; then
    echo -e "  [${FAIL}] ${RED}Binário não encontrado em $BINARY_PATH${NC}"
    exit 1
fi

BINARY_SIZE=$(du -sh "$BINARY_PATH" | awk '{print $1}')
echo -e "  [${PASS}] ${GREEN}Binário gerado: $BINARY_SIZE${NC}"

# ─── Empacotamento ────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 2 — Empacotamento${NC}"
echo ""

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/$ASSET_NAME"

cp "$BINARY_PATH"             "$DIST_DIR/$ASSET_NAME/"
cp "$PROJECT_ROOT/README.md"  "$DIST_DIR/$ASSET_NAME/"
cp "$PROJECT_ROOT/LICENSE"    "$DIST_DIR/$ASSET_NAME/"
cp "$PROJECT_ROOT/NOTICE"     "$DIST_DIR/$ASSET_NAME/"

(cd "$DIST_DIR" && tar -czf "${ASSET_NAME}.tar.gz" "$ASSET_NAME")
rm -rf "$DIST_DIR/$ASSET_NAME"

ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | awk '{print $1}')
echo -e "  [${PASS}] ${GREEN}Arquivo criado: $ARCHIVE ($ARCHIVE_SIZE)${NC}"

# ─── Verificação ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Etapa 3 — Verificação${NC}"
echo ""

TMPDIR_TEST=$(mktemp -d)
tar -xzf "$ARCHIVE" -C "$TMPDIR_TEST"
EXTRACTED_BINARY="$TMPDIR_TEST/$ASSET_NAME/$BINARY_NAME"

if [[ -x "$EXTRACTED_BINARY" ]]; then
    VERSION_OUTPUT=$("$EXTRACTED_BINARY" --version 2>/dev/null || echo "(sem --version)")
    echo -e "  [${PASS}] ${GREEN}Binário extraído e executável: $VERSION_OUTPUT${NC}"
else
    echo -e "  [${FAIL}] ${RED}Binário extraído não é executável${NC}"
fi
rm -rf "$TMPDIR_TEST"

# ─── Resumo ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                      Resumo                         ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ Pacote gerado com sucesso!${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Arquivo:${NC}"
echo "  $ARCHIVE"
echo ""
echo -e "${BOLD}Para publicar como GitHub Release:${NC}"
echo ""
echo "  git tag v0.1.0"
echo "  git push --tags"
echo ""
echo "  O GitHub Actions irá construir para todas as plataformas"
echo "  e publicar automaticamente em:"
echo "  https://github.com/fabioschorn/physarum-attack-paths/releases"
echo ""

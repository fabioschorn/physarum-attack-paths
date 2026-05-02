#!/usr/bin/env bash
#
# check-env.sh — Verifica se o ambiente está pronto para compilar o projeto
#                physarum-attack-paths.
#
# Uso:
#   chmod +x Utilities/check-env.sh
#   ./Utilities/check-env.sh
#
# Baseado em:
#   https://doc.rust-lang.org/stable/book/ch01-01-installation.html
#   https://sh.rustup.rs

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

# ─── Configurações do projeto ─────────────────────────────────────────────────
REQUIRED_RUST_MAJOR=1
REQUIRED_RUST_MINOR=78
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

errors=0
warnings=0

# ─── Funções de output ────────────────────────────────────────────────────────
section() {
    echo ""
    echo -e "${BOLD}── $1${NC}"
}

pass()  { echo -e "  [${PASS}] $1"; }
fail()  { echo -e "  [${FAIL}] ${RED}$1${NC}"; ((errors+=1)); }
warn()  { echo -e "  [${WARN}] ${YELLOW}$1${NC}"; ((warnings+=1)); }
info()  { echo -e "  [${INFO}] ${BLUE}$1${NC}"; }
hint()  { echo -e "      ${YELLOW}Solução:${NC} $1"; }

# Compara versões semânticas: retorna 0 se $1 >= $2
version_gte() {
    local installed="${1//[^0-9.]*/}"
    local required="${2//[^0-9.]*/}"
    printf '%s\n%s\n' "$required" "$installed" | sort -V -C
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║   Physarum Attack Paths — Verificação de Ambiente    ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
info "Raiz do projeto : $PROJECT_ROOT"
info "Data            : $(date '+%Y-%m-%d %H:%M:%S')"

# ─── 1. Sistema operacional ───────────────────────────────────────────────────
section "1. Sistema Operacional"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        MACOS_VER="$(sw_vers -productVersion)"
        pass "macOS $MACOS_VER — arquitetura: $ARCH"
        ;;
    Linux)
        DISTRO="$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo 'Linux')"
        pass "$DISTRO — arquitetura: $ARCH"
        ;;
    *)
        warn "Sistema não reconhecido: $OS. Este script foi testado em macOS e Linux."
        ;;
esac

# ─── 2. Ferramentas de linha de comando (macOS) ───────────────────────────────
if [[ "$OS" == "Darwin" ]]; then
    section "2. Xcode Command Line Tools (macOS)"

    if xcode-select -p &>/dev/null 2>&1; then
        XCODE_PATH="$(xcode-select -p)"
        pass "Instaladas em: $XCODE_PATH"
    else
        fail "Xcode Command Line Tools não encontradas."
        hint "Execute: xcode-select --install"
        echo "        Aguarde a instalação e execute este script novamente."
    fi
else
    section "2. Build Essentials (Linux)"

    if command -v gcc &>/dev/null || command -v clang &>/dev/null; then
        pass "Compilador C encontrado"
    else
        fail "Nenhum compilador C encontrado (gcc ou clang)."
        hint "Execute: sudo apt install build-essential    # Debian/Ubuntu"
        hint "     ou: sudo dnf install gcc               # Fedora/RHEL"
    fi
fi

# ─── 3. Linker C (cc) ────────────────────────────────────────────────────────
section "3. Linker C (necessário para compilar Rust)"

if command -v cc &>/dev/null; then
    CC_VER="$(cc --version 2>&1 | head -1)"
    pass "cc encontrado: $CC_VER"
elif command -v clang &>/dev/null; then
    CLANG_VER="$(clang --version 2>&1 | head -1)"
    pass "clang encontrado: $CLANG_VER"
elif command -v gcc &>/dev/null; then
    GCC_VER="$(gcc --version 2>&1 | head -1)"
    pass "gcc encontrado: $GCC_VER"
else
    fail "Nenhum linker C encontrado. O Rust precisa de um para gerar binários."
    if [[ "$OS" == "Darwin" ]]; then
        hint "Execute: xcode-select --install"
    fi
fi

# ─── 4. curl ─────────────────────────────────────────────────────────────────
section "4. curl (necessário para instalar rustup)"

if command -v curl &>/dev/null; then
    CURL_VER="$(curl --version | head -1)"
    pass "$CURL_VER"
else
    fail "curl não encontrado."
    hint "No macOS, curl vem pré-instalado. Verifique sua instalação do sistema."
fi

# ─── 5. rustup ───────────────────────────────────────────────────────────────
section "5. rustup (gerenciador de toolchains do Rust)"

if command -v rustup &>/dev/null; then
    RUSTUP_VER="$(rustup --version 2>/dev/null | awk '{print $2}')"
    pass "rustup $RUSTUP_VER"

    info "Para atualizar rustup e todas as toolchains: rustup update"
else
    fail "rustup não encontrado. O Rust não está instalado."
    hint "Execute o seguinte comando para instalar:"
    echo ""
    echo "        curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh"
    echo ""
    echo "        Após a instalação, reinicie o terminal e execute este script novamente."
fi

# ─── 6. rustc (compilador) ───────────────────────────────────────────────────
section "6. rustc (compilador do Rust)"

REQUIRED_VERSION="${REQUIRED_RUST_MAJOR}.${REQUIRED_RUST_MINOR}"

if command -v rustc &>/dev/null; then
    RUSTC_VER="$(rustc --version | awk '{print $2}')"

    if version_gte "$RUSTC_VER" "$REQUIRED_VERSION"; then
        pass "rustc $RUSTC_VER  (versão mínima exigida pelo projeto: $REQUIRED_VERSION)"
    else
        fail "rustc $RUSTC_VER está abaixo da versão mínima exigida ($REQUIRED_VERSION)."
        hint "Execute: rustup update stable"
    fi
else
    fail "rustc não encontrado."
    hint "Instale o Rust via rustup (veja o passo 5 acima)."
fi

# ─── 7. cargo ────────────────────────────────────────────────────────────────
section "7. cargo (gerenciador de pacotes e build)"

if command -v cargo &>/dev/null; then
    CARGO_VER="$(cargo --version | awk '{print $2}')"
    pass "cargo $CARGO_VER"
else
    fail "cargo não encontrado."
    hint "O cargo é instalado automaticamente com rustup. Reinstale o Rust."
fi

# ─── 8. PATH ─────────────────────────────────────────────────────────────────
section "8. PATH — \$HOME/.cargo/bin"

CARGO_BIN="$HOME/.cargo/bin"

if [[ ":$PATH:" == *":${CARGO_BIN}:"* ]]; then
    pass "\$HOME/.cargo/bin está no PATH"
else
    warn "\$HOME/.cargo/bin NÃO está no PATH."
    echo ""
    echo "      Isso pode impedir que rustc, cargo e outros binários sejam encontrados."
    hint "Adicione ao seu ~/.zshrc (zsh) ou ~/.bashrc (bash):"
    echo ""
    echo '        export PATH="$HOME/.cargo/bin:$PATH"'
    echo ""
    echo "      Em seguida execute: source ~/.zshrc"
fi

# ─── 9. Toolchain ativa ───────────────────────────────────────────────────────
section "9. Toolchain Rust ativa"

if command -v rustup &>/dev/null; then
    ACTIVE_TOOLCHAIN="$(rustup show active-toolchain 2>/dev/null || echo 'desconhecida')"
    pass "Toolchain ativa: $ACTIVE_TOOLCHAIN"

    if rustup toolchain list 2>/dev/null | grep -q "^stable"; then
        pass "Toolchain 'stable' disponível"
    else
        warn "Toolchain 'stable' não encontrada."
        hint "Execute: rustup toolchain install stable"
    fi

    info "Toolchains instaladas:"
    rustup toolchain list 2>/dev/null | while IFS= read -r line; do
        echo "        $line"
    done
fi

# ─── 10. git ─────────────────────────────────────────────────────────────────
section "10. git (controle de versão)"

if command -v git &>/dev/null; then
    GIT_VER="$(git --version | awk '{print $3}')"
    pass "git $GIT_VER"
else
    warn "git não encontrado. Recomendado para controle de versão do projeto."
    if [[ "$OS" == "Darwin" ]]; then
        hint "Execute: xcode-select --install  (instala git junto com as ferramentas de linha de comando)"
    fi
fi

# ─── 11. Estrutura do projeto ─────────────────────────────────────────────────
section "11. Estrutura do Projeto"

if [[ -f "$PROJECT_ROOT/Cargo.toml" ]]; then
    pass "Cargo.toml (workspace) encontrado em: $PROJECT_ROOT"
else
    fail "Cargo.toml não encontrado em: $PROJECT_ROOT"
    hint "Certifique-se de estar executando o script a partir do diretório correto."
fi

if [[ -d "$PROJECT_ROOT/crates" ]]; then
    CRATE_COUNT="$(ls "$PROJECT_ROOT/crates" | wc -l | tr -d ' ')"
    pass "Diretório crates/ encontrado — $CRATE_COUNT crate(s):"
    ls "$PROJECT_ROOT/crates" | while IFS= read -r crate; do
        echo "        • $crate"
    done
else
    warn "Diretório crates/ ainda não existe. Os crates ainda não foram criados."
fi

if [[ -d "$PROJECT_ROOT/Utilities" ]]; then
    pass "Diretório Utilities/ encontrado"
fi

# ─── 12. Validação do workspace Rust ─────────────────────────────────────────
section "12. Validação do Workspace Rust"

if command -v cargo &>/dev/null && [[ -f "$PROJECT_ROOT/Cargo.toml" ]]; then
    if cargo metadata \
           --manifest-path "$PROJECT_ROOT/Cargo.toml" \
           --no-deps \
           --quiet \
           &>/dev/null 2>&1; then
        pass "Workspace válido (cargo metadata OK)"
    else
        fail "Workspace com erros. Detalhes:"
        cargo metadata \
            --manifest-path "$PROJECT_ROOT/Cargo.toml" \
            --no-deps \
            --quiet 2>&1 | head -20 | while IFS= read -r line; do
            echo "        $line"
        done
    fi
fi

# ─── Resumo final ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                      Resumo                         ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${NC}"

if [[ $errors -eq 0 && $warnings -eq 0 ]]; then
    echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ Tudo certo! O ambiente está pronto para compilar.  ${BLUE}║${NC}"
elif [[ $errors -eq 0 ]]; then
    echo -e "${BOLD}${BLUE}║${NC}  ${YELLOW}⚠ $warnings aviso(s). O projeto deve compilar, mas      ${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  ${YELLOW}  revise os itens marcados com ⚠ acima.               ${BLUE}║${NC}"
else
    echo -e "${BOLD}${BLUE}║${NC}  ${RED}✘ $errors erro(s) e $warnings aviso(s) encontrados.           ${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  ${RED}  Corrija os itens marcados com ✘ antes de compilar.  ${BLUE}║${NC}"
fi

echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Próximos passos se tudo OK
if [[ $errors -eq 0 ]]; then
    echo -e "${BOLD}Próximos passos:${NC}"
    echo ""
    echo "  Para compilar o projeto:"
    echo "    cd $PROJECT_ROOT"
    echo "    cargo build"
    echo ""
    echo "  Para rodar os testes do crate de protocolo:"
    echo "    cargo test -p physarum-protocol"
    echo ""
    echo "  Para iniciar o servidor coordinator:"
    echo "    cargo run -p physarum-server -- --listen 127.0.0.1:8080"
    echo ""
fi

# Código de saída: 0 = sucesso, 1 = erros encontrados
exit $errors

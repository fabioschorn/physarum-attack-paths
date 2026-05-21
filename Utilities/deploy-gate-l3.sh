#!/usr/bin/env bash
#
# deploy-gate-l3.sh — Compila todos os artefatos Gate L.3 e faz upload para S3.
#
# Gate L.3 adiciona physarum-packet-observer (userspace) e seu bytecode eBPF
# (physarum-packet-observer-ebpf, tc ingress ICMP) ao conjunto de artefatos.
# physarum-agent é recompilado com --sense-icmp-packet e --sense-tcp-socket-state.
#
# Docker Build Cloud é tentado primeiro; fallback automático para Docker local.
#
# Uso:
#   ./Utilities/deploy-gate-l3.sh
#   ./Utilities/deploy-gate-l3.sh --skip-build     # pula builds (já compilados)
#   ./Utilities/deploy-gate-l3.sh --skip-upload    # pula upload S3
#   ./Utilities/deploy-gate-l3.sh --dry-run        # mostra comandos sem executar
#
# Pré-requisitos:
#   - Docker em execução (para build Linux x86_64)
#   - AWS CLI configurado com credenciais da conta 168740128169
#   - Rust nightly + componente rust-src (para eBPF bytecode)

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

# ─── Configuração Gate L.3 ───────────────────────────────────────────────────
GATE="gate-l3"
DOCKER_IMAGE="rust:1-slim-bookworm"
LINUX_TARGET="x86_64-unknown-linux-gnu"
ARTIFACT_BUCKET="physarum-artifacts-168740128169"
ARTIFACT_PREFIX="physarum-attack-paths/dev/linux-x86_64"
ARTIFACT_REGION="us-east-1"
EXPECTED_ACCOUNT="168740128169"
CLOUD_BUILDER="cloud-fs09-physarum-attack-paths"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$PROJECT_ROOT/target/gate-l3-linux-x86_64"
BINARIES=("physarum-agent" "physarum-server" "physarum-packet-observer")
EBPF_BYTECODE="physarum-packet-observer-ebpf"
EBPF_TARGET="bpfel-unknown-none"

# ─── Argumentos ──────────────────────────────────────────────────────────────
SKIP_BUILD=false
SKIP_UPLOAD=false
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --skip-build)  SKIP_BUILD=true ;;
    --skip-upload) SKIP_UPLOAD=true ;;
    --dry-run)     DRY_RUN=true ;;
    --help|-h)
      echo "Uso: $0 [--skip-build] [--skip-upload] [--dry-run]"
      exit 0
      ;;
    *)
      echo -e "${RED}Argumento desconhecido: $arg${NC}"
      exit 1
      ;;
  esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────
overall_start=$(date +%s)
errors=0

section() { echo ""; echo -e "${BOLD}── $1${NC}"; }
pass()    { echo -e "  [${PASS}] $1"; }
fail()    { echo -e "  [${FAIL}] ${RED}$1${NC}"; ((errors+=1)); }
warn()    { echo -e "  [${WARN}] ${YELLOW}$1${NC}"; }
info()    { echo -e "  [${INFO}] ${BLUE}$1${NC}"; }

elapsed() {
  local start=$1 end
  end=$(date +%s)
  echo $(( end - start ))s
}

run_or_dry() {
  local label="$1"; shift
  if [ "$DRY_RUN" = true ]; then
    echo -e "  ${YELLOW}[DRY-RUN]${NC} $*"
  else
    local t; t=$(date +%s)
    if "$@" 2>&1 | sed 's/^/    /'; then
      pass "$label ($(elapsed "$t"))"
    else
      fail "$label falhou"
      return 1
    fi
  fi
}

# ─── Cabeçalho ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║   Physarum Attack Paths — Deploy Gate L.3 (ICMP tc ingress) ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Projeto        : $PROJECT_ROOT"
info "Gate           : $GATE"
info "Target Linux   : $LINUX_TARGET"
info "Docker image   : $DOCKER_IMAGE"
info "S3 bucket      : $ARTIFACT_BUCKET"
info "S3 prefix      : $ARTIFACT_PREFIX"
info "Iniciado       : $(date '+%Y-%m-%d %H:%M:%S')"
[ "$DRY_RUN" = true ]     && warn "Modo dry-run ativo — nenhum comando destrutivo será executado"
[ "$SKIP_BUILD" = true ]  && warn "Build ignorado (--skip-build)"
[ "$SKIP_UPLOAD" = true ] && warn "Upload S3 ignorado (--skip-upload)"

# ─── 1. Pré-requisitos ───────────────────────────────────────────────────────
section "1. Pré-requisitos"

if ! command -v docker &>/dev/null; then
  fail "Docker não encontrado."
  exit 1
fi
if ! docker info &>/dev/null; then
  fail "Docker não está em execução."
  exit 1
fi
pass "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

if ! command -v aws &>/dev/null; then
  fail "AWS CLI não encontrado."
  exit 1
fi
pass "AWS CLI $(aws --version 2>&1 | awk '{print $1}')"

# ─── 2. Verificação de conta AWS ─────────────────────────────────────────────
section "2. Verificação de conta AWS"

ACTUAL_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "FALHA")

if [ "$ACTUAL_ACCOUNT" = "FALHA" ]; then
  fail "Não foi possível obter a identidade AWS."
  exit 1
fi

if [ "$ACTUAL_ACCOUNT" != "$EXPECTED_ACCOUNT" ]; then
  fail "Conta incorreta: esperado $EXPECTED_ACCOUNT, encontrado $ACTUAL_ACCOUNT"
  exit 1
fi
pass "Conta AWS: $ACTUAL_ACCOUNT (OK)"
info "Identidade: $(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)"

# ─── 3. Verificação do bucket S3 ─────────────────────────────────────────────
section "3. Verificação do bucket S3"

if aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" --region "$ARTIFACT_REGION" &>/dev/null; then
  pass "Bucket s3://$ARTIFACT_BUCKET existe e está acessível"
else
  fail "Bucket s3://$ARTIFACT_BUCKET não encontrado ou sem permissão."
  exit 1
fi

section "3b. Artefatos atuais no S3 (antes do upload)"
aws s3 ls "s3://${ARTIFACT_BUCKET}/${ARTIFACT_PREFIX}/" --region "$ARTIFACT_REGION" 2>/dev/null | \
  awk '{printf "    %s %s  %s  (%s bytes)\n", $1, $2, $4, $3}' || true

# ─── 4. Detectar Docker Build Cloud ──────────────────────────────────────────
section "4. Docker Build Cloud"

BUILDER="default"
if docker buildx inspect "$CLOUD_BUILDER" &>/dev/null 2>&1; then
  BUILDER="$CLOUD_BUILDER"
  pass "Docker Build Cloud disponível: $CLOUD_BUILDER"
else
  warn "Docker Build Cloud ($CLOUD_BUILDER) não disponível — usando builder local"
fi
info "Builder selecionado: $BUILDER"

# ─── 5. Build binários Linux x86_64 ──────────────────────────────────────────
section "5. Build binários Linux x86_64"

if [ "$SKIP_BUILD" = true ]; then
  warn "Build ignorado (--skip-build). Verificando binários existentes..."
  for bin in "${BINARIES[@]}"; do
    if [ -f "$TARGET_DIR/release/$bin" ]; then
      SIZE=$(du -sh "$TARGET_DIR/release/$bin" | awk '{print $1}')
      pass "$bin  ($SIZE)"
    else
      fail "$bin não encontrado em $TARGET_DIR/release/ — remova --skip-build"
    fi
  done
else
  mkdir -p "$TARGET_DIR/release"

  build_start=$(date +%s)
  echo ""

  if [ "$BUILDER" != "default" ]; then
    # ── Docker Build Cloud path ────────────────────────────────────────────────
    # docker buildx build --builder sends the build to the cloud builder.
    # Binaries are extracted locally via --output type=local.
    info "Usando Docker Build Cloud: $BUILDER"
    info "Enviando contexto e compilando no cloud (primeira execução pode demorar)"

    TMP_DOCKERFILE=$(mktemp "${TMPDIR:-/tmp}/Dockerfile.gate-l3.XXXXXX")
    cat > "$TMP_DOCKERFILE" <<'DOCKERFILE_CONTENT'
FROM rust:1-slim-bookworm AS builder
RUN apt-get update -qq && apt-get install -y --no-install-recommends gcc libc6-dev
WORKDIR /workspace
COPY . .
RUN cargo build --release \
    -p physarum-agent \
    -p physarum-server \
    -p physarum-packet-observer

FROM scratch AS export
COPY --from=builder /workspace/target/release/physarum-agent .
COPY --from=builder /workspace/target/release/physarum-server .
COPY --from=builder /workspace/target/release/physarum-packet-observer .
DOCKERFILE_CONTENT

    # Create a temporary .dockerignore to avoid sending target/ to the cloud.
    CREATED_DOCKERIGNORE=false
    if [ ! -f "${PROJECT_ROOT}/.dockerignore" ]; then
      cat > "${PROJECT_ROOT}/.dockerignore" <<'DOCKERIGNORE_CONTENT'
target/
.git/
.claude/
*.local.ini
*.local.json
.keys/
DOCKERIGNORE_CONTENT
      CREATED_DOCKERIGNORE=true
    fi

    CLOUD_BUILD_CMD=(
      docker buildx build
      --builder "$BUILDER"
      --platform linux/amd64
      --output "type=local,dest=${TARGET_DIR}/release"
      --target export
      -f "$TMP_DOCKERFILE"
      "$PROJECT_ROOT"
    )

    if [ "$DRY_RUN" = true ]; then
      echo -e "  ${YELLOW}[DRY-RUN]${NC} ${CLOUD_BUILD_CMD[*]}"
    else
      if "${CLOUD_BUILD_CMD[@]}" 2>&1 | sed 's/^/    /'; then
        pass "Docker Build Cloud concluído em $(elapsed "$build_start")"
      else
        fail "Build Docker Build Cloud falhou — verifique a saída acima"
        [ "$CREATED_DOCKERIGNORE" = true ] && rm -f "${PROJECT_ROOT}/.dockerignore"
        rm -f "$TMP_DOCKERFILE"
        exit 1
      fi
      [ "$CREATED_DOCKERIGNORE" = true ] && rm -f "${PROJECT_ROOT}/.dockerignore"
    fi
    rm -f "$TMP_DOCKERFILE"

  else
    # ── Local Docker fallback (docker run com volume mounts) ──────────────────
    info "Usando builder local (docker run): $DOCKER_IMAGE"
    info "Cache do target preservado em: $TARGET_DIR"

    BUILD_CMD=(
      docker run --rm
      --platform linux/amd64
      -v "${PROJECT_ROOT}:/workspace:ro"
      -v "${TARGET_DIR}:/target"
      -e "CARGO_TARGET_DIR=/target"
      -w /workspace
      "$DOCKER_IMAGE"
      bash -c "
        set -euxo pipefail
        apt-get update -qq && apt-get install -y --no-install-recommends gcc libc6-dev 2>&1
        cargo build --release -p physarum-agent -p physarum-server -p physarum-packet-observer 2>&1
      "
    )

    if [ "$DRY_RUN" = true ]; then
      echo -e "  ${YELLOW}[DRY-RUN]${NC} ${BUILD_CMD[*]}"
    else
      if "${BUILD_CMD[@]}"; then
        pass "Build Docker local concluído em $(elapsed "$build_start")"
      else
        fail "Build Docker local falhou — verifique a saída acima"
        exit 1
      fi
    fi
  fi

  echo ""
  section "5b. Binários gerados"
  for bin in "${BINARIES[@]}"; do
    if [ "$DRY_RUN" = true ]; then
      info "[DRY-RUN] $bin → $TARGET_DIR/release/$bin"
    elif [ -f "$TARGET_DIR/release/$bin" ]; then
      SIZE=$(du -sh "$TARGET_DIR/release/$bin" | awk '{print $1}')
      pass "$bin  ($SIZE)  → $TARGET_DIR/release/$bin"
    else
      fail "$bin não encontrado após o build"
      errors=$((errors + 1))
    fi
  done
fi

[ "$errors" -gt 0 ] && { echo ""; fail "Abortando — binários ausentes."; exit 1; }

# ─── 6. Build eBPF bytecode (physarum-packet-observer-ebpf) ──────────────────
section "6. Build eBPF bytecode (tc ingress ICMP)"

EBPF_DIR="$PROJECT_ROOT/crates/physarum-packet-observer-ebpf"
EBPF_OUT_DIR="$EBPF_DIR/target/$EBPF_TARGET/release"
EBPF_BYTECODE_PATH="$EBPF_OUT_DIR/$EBPF_BYTECODE"

if [ "$SKIP_BUILD" = true ]; then
  warn "Build eBPF ignorado (--skip-build). Verificando bytecode existente..."
  if [ -f "$EBPF_BYTECODE_PATH" ]; then
    SIZE=$(du -sh "$EBPF_BYTECODE_PATH" | awk '{print $1}')
    pass "$EBPF_BYTECODE  ($SIZE)"
  else
    fail "$EBPF_BYTECODE não encontrado em $EBPF_OUT_DIR — remova --skip-build"
    errors=$((errors + 1))
  fi
else
  # Use docker buildx build (cloud builder if available) to compile the eBPF bytecode.
  # Use PROJECT_ROOT as context (same as section 5) with -f - (stdin heredoc) to avoid
  # temp files in /private/tmp which cause xattr permission errors on macOS + Docker Desktop.
  # The inline Dockerfile overrides rust-toolchain.toml to remove `targets = ["bpfel-unknown-none"]`
  # because that target has no prebuilt rust-std; we compile std from source with -Z build-std=core.
  info "Compilando $EBPF_BYTECODE via docker buildx (builder: $BUILDER)"

  mkdir -p "$EBPF_OUT_DIR"

  CREATED_DOCKERIGNORE_EBPF=false
  if [ ! -f "${PROJECT_ROOT}/.dockerignore" ]; then
    cat > "${PROJECT_ROOT}/.dockerignore" <<'DOCKERIGNORE_CONTENT'
target/
.git/
.claude/
*.local.ini
*.local.json
.keys/
DOCKERIGNORE_CONTENT
    CREATED_DOCKERIGNORE_EBPF=true
  fi

  ebpf_start=$(date +%s)
  if [ "$DRY_RUN" = true ]; then
    echo -e "  ${YELLOW}[DRY-RUN]${NC} docker buildx build --builder $BUILDER --platform linux/amd64 --output type=local,dest=${EBPF_OUT_DIR} --target export -f - ${PROJECT_ROOT} <<HEREDOC"
  else
    # Use exit-code capture outside the if condition to avoid bash heredoc-in-if parsing issues.
    _ebpf_exit=0
    docker buildx build \
        --builder "$BUILDER" \
        --platform linux/amd64 \
        --output "type=local,dest=${EBPF_OUT_DIR}" \
        --target export \
        -f - \
        "$PROJECT_ROOT" 2>&1 <<'EBPF_DOCKERFILE' | sed 's/^/    /' || _ebpf_exit=$?
FROM debian:bookworm-slim AS ebpf-builder
# LLVM 14 is in bookworm's default repos; bpf-linker 0.9.13 uses llvm-sys 140.x.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates gcc libc6-dev llvm-14 libclang-14-dev && \
    rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- --default-toolchain nightly --component rust-src --no-modify-path -y
ENV PATH="/root/.cargo/bin:${PATH}" \
    RUSTUP_HOME="/root/.rustup" \
    CARGO_HOME="/root/.cargo" \
    LLVM_SYS_140_PREFIX="/usr/lib/llvm-14"
RUN cargo install bpf-linker@0.9.13
WORKDIR /build
COPY crates/physarum-packet-observer-ebpf/Cargo.toml ./Cargo.toml
COPY crates/physarum-packet-observer-ebpf/src ./src
RUN RUSTUP_TOOLCHAIN=nightly cargo build --release --target bpfel-unknown-none -Z build-std=core

FROM scratch AS export
COPY --from=ebpf-builder /build/target/bpfel-unknown-none/release/physarum-packet-observer-ebpf .
EBPF_DOCKERFILE

    if [ "$_ebpf_exit" -eq 0 ]; then
      pass "eBPF bytecode compilado em $(elapsed "$ebpf_start")"
      if [ -f "$EBPF_BYTECODE_PATH" ]; then
        SIZE=$(du -sh "$EBPF_BYTECODE_PATH" | awk '{print $1}')
        pass "$EBPF_BYTECODE  ($SIZE)  → $EBPF_BYTECODE_PATH"
      else
        fail "$EBPF_BYTECODE não encontrado após build"
        errors=$((errors + 1))
      fi
    else
      fail "Build eBPF falhou (código $_ebpf_exit) — verifique a saída acima"
      [ "$CREATED_DOCKERIGNORE_EBPF" = true ] && rm -f "${PROJECT_ROOT}/.dockerignore"
      exit 1
    fi
    [ "$CREATED_DOCKERIGNORE_EBPF" = true ] && rm -f "${PROJECT_ROOT}/.dockerignore"
  fi
fi

[ "$errors" -gt 0 ] && { echo ""; fail "Abortando — bytecode ausente."; exit 1; }

# ─── 7. Upload para S3 ───────────────────────────────────────────────────────
section "7. Upload para S3"

if [ "$SKIP_UPLOAD" = true ]; then
  warn "Upload ignorado (--skip-upload)"
else
  for bin in "${BINARIES[@]}"; do
    S3_URI="s3://${ARTIFACT_BUCKET}/${ARTIFACT_PREFIX}/${bin}"
    info "Upload: $bin  →  $S3_URI"
    run_or_dry "aws s3 cp $bin" \
      aws s3 cp "$TARGET_DIR/release/$bin" "$S3_URI" \
        --region "$ARTIFACT_REGION" \
        --no-progress
  done

  S3_EBPF_URI="s3://${ARTIFACT_BUCKET}/${ARTIFACT_PREFIX}/${EBPF_BYTECODE}"
  info "Upload: $EBPF_BYTECODE  →  $S3_EBPF_URI"
  if [ "$DRY_RUN" = true ]; then
    echo -e "  ${YELLOW}[DRY-RUN]${NC} aws s3 cp $EBPF_BYTECODE_PATH $S3_EBPF_URI"
  else
    aws s3 cp "$EBPF_BYTECODE_PATH" "$S3_EBPF_URI" \
      --region "$ARTIFACT_REGION" \
      --no-progress
    pass "eBPF bytecode uploaded"
  fi

  if [ "$DRY_RUN" = false ]; then
    echo ""
    info "Artefatos no S3 após upload:"
    aws s3 ls "s3://${ARTIFACT_BUCKET}/${ARTIFACT_PREFIX}/" --region "$ARTIFACT_REGION" | \
      awk '{printf "    %s %s  %s  (%s bytes)\n", $1, $2, $4, $3}'
  fi
fi

# ─── 8. Resumo e próximos passos ─────────────────────────────────────────────
ELAPSED_TOTAL=$(elapsed "$overall_start")

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                          Resumo                              ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
if [ "$errors" -eq 0 ]; then
  echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ Gate L.3 deploy concluído em ${ELAPSED_TOTAL}.${NC}"
  echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}  Builder: $BUILDER${NC}"
else
  echo -e "${BOLD}${BLUE}║${NC}  ${RED}✘ $errors erro(s). Corrija acima e tente novamente.${NC}"
fi
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ "$errors" -eq 0 ]; then
  echo ""
  echo -e "${BOLD}Passo 1 — terraform apply (Gate L.3):${NC}"
  echo ""
  echo "  cd $PROJECT_ROOT/examples/aws-lab/terraform"
  echo ""
  echo '  MY_IP=$(curl -s -4 ifconfig.me)'
  echo '  AMI_ID=$(aws ec2 describe-images \'
  echo '    --owners amazon \'
  echo '    --filters "Name=name,Values=al2023-ami-*-kernel-*-x86_64" "Name=state,Values=available" \'
  echo '    --query '"'"'sort_by(Images, &CreationDate)[-1].ImageId'"'"' \'
  echo '    --output text --region us-east-1)'
  echo ""
  echo "  terraform apply \\"
  echo "    -var=\"lab_phase=gate-l3\" \\"
  echo "    -var=\"operator_cidr=\${MY_IP}/32\" \\"
  echo "    -var=\"ami_id_override=\${AMI_ID}\" \\"
  echo "    -var=\"enable_artifact_download=true\" \\"
  echo "    -var=\"artifact_bucket=${ARTIFACT_BUCKET}\" \\"
  echo "    -var=\"enable_packet_observer=true\" \\"
  echo "    -var=\"enable_discovery=true\" \\"
  echo "    -var=\"discovery_scope_mode=local-interfaces\""
  echo ""
  echo -e "${BOLD}Passo 2 — aguardar cloud-init (~3 min), depois validar com Ansible:${NC}"
  echo ""
  echo "  # Verificar instâncias descobertas pelo inventário dinâmico:"
  echo "  ansible-inventory -i examples/aws-lab/ansible/aws_ec2.yml --graph"
  echo ""
  echo -e "${BOLD}Passo 3 — validação Gate L.3 (ansible, inventário dinâmico):${NC}"
  echo ""
  echo "  cd $PROJECT_ROOT"
  echo "  ansible-playbook -i examples/aws-lab/ansible/aws_ec2.yml \\"
  echo "    examples/aws-lab/ansible/validate-gate-l3-icmp-stimulus.yml"
  echo ""
  echo -e "${BOLD}Passo 4 — destruir lab ao terminar (sempre):${NC}"
  echo ""
  echo "  cd $PROJECT_ROOT/examples/aws-lab/terraform"
  echo "  terraform destroy \\"
  echo "    -var=\"lab_phase=gate-l3\" \\"
  echo "    -var=\"operator_cidr=\${MY_IP}/32\" \\"
  echo "    -var=\"ami_id_override=\${AMI_ID}\" \\"
  echo "    -var=\"enable_artifact_download=true\" \\"
  echo "    -var=\"artifact_bucket=${ARTIFACT_BUCKET}\" \\"
  echo "    -var=\"enable_packet_observer=true\" \\"
  echo "    -var=\"enable_discovery=true\" \\"
  echo "    -var=\"discovery_scope_mode=local-interfaces\""
  echo ""
fi

#!/usr/bin/env bash
#
# deploy-gate-l2.sh — Compila physarum-agent + physarum-server para
#                     x86_64-unknown-linux-gnu via Docker e faz upload para S3.
#
# Gate L.2 adiciona o caminho inbound (AcceptEstablished) ao ebpf_seed_loop,
# por isso physarum-agent precisa ser recompilado. O physarum-ebpf-observer
# e o bytecode eBPF não mudaram e permanecem no S3.
#
# Uso:
#   ./Utilities/deploy-gate-l2.sh
#   ./Utilities/deploy-gate-l2.sh --skip-build     # pula o Docker build (já compilado)
#   ./Utilities/deploy-gate-l2.sh --skip-upload    # pula o upload S3
#   ./Utilities/deploy-gate-l2.sh --dry-run        # mostra comandos sem executar
#
# Pré-requisitos:
#   - Docker em execução (para build Linux x86_64)
#   - AWS CLI configurado com credenciais da conta 168740128169
#   - aws sts get-caller-identity deve retornar a conta correta

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

# ─── Configuração Gate L.2 ───────────────────────────────────────────────────
GATE="gate-l2"
DOCKER_IMAGE="rust:1-slim-bookworm"
LINUX_TARGET="x86_64-unknown-linux-gnu"
ARTIFACT_BUCKET="physarum-artifacts-168740128169"
# Usa o prefix padrão de variables.tf — compartilhado com gate-l e gate-l1.
ARTIFACT_PREFIX="physarum-attack-paths/dev/linux-x86_64"
ARTIFACT_REGION="us-east-1"
EXPECTED_ACCOUNT="168740128169"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$PROJECT_ROOT/target/gate-l2-linux-x86_64"
# Observer não muda — apenas agent e server precisam de rebuild.
BINARIES=("physarum-agent" "physarum-server")

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
echo -e "${BOLD}${BLUE}║   Physarum Attack Paths — Deploy Gate L.2 (inbound eBPF)    ║${NC}"
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
[ "$SKIP_BUILD" = true ]  && warn "Build Docker ignorado (--skip-build)"
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

# ─── 4. Build via Docker ─────────────────────────────────────────────────────
section "4. Build Linux x86_64 via Docker"

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
  mkdir -p "$TARGET_DIR"
  info "Iniciando build Docker (primeira execução pode demorar — pull da imagem Rust)"
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
      cargo build --release -p physarum-agent -p physarum-server 2>&1
    "
  )

  echo ""
  echo -e "  ${BOLD}Executando build Docker...${NC}"
  echo ""

  build_start=$(date +%s)
  if [ "$DRY_RUN" = true ]; then
    echo -e "  ${YELLOW}[DRY-RUN]${NC} ${BUILD_CMD[*]}"
  else
    if "${BUILD_CMD[@]}"; then
      pass "Build Docker concluído em $(elapsed "$build_start")"
    else
      fail "Build Docker falhou — verifique a saída acima"
      exit 1
    fi
  fi

  echo ""
  section "4b. Binários gerados"
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

# ─── 5. Upload para S3 ───────────────────────────────────────────────────────
section "5. Upload para S3"

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

  if [ "$DRY_RUN" = false ]; then
    echo ""
    info "Artefatos no S3 após upload:"
    aws s3 ls "s3://${ARTIFACT_BUCKET}/${ARTIFACT_PREFIX}/" --region "$ARTIFACT_REGION" | \
      awk '{printf "    %s %s  %s  (%s bytes)\n", $1, $2, $4, $3}'
  fi
fi

# ─── 6. Próximos passos ───────────────────────────────────────────────────────
ELAPSED_TOTAL=$(elapsed "$overall_start")

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                          Resumo                              ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
if [ "$errors" -eq 0 ]; then
  echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ Gate L.2 deploy concluído em ${ELAPSED_TOTAL}.${NC}"
else
  echo -e "${BOLD}${BLUE}║${NC}  ${RED}✘ $errors erro(s). Corrija acima e tente novamente.${NC}"
fi
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ "$errors" -eq 0 ]; then
  echo ""
  echo -e "${BOLD}Passo 1 — terraform apply (Gate L.2):${NC}"
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
  echo "    -var=\"lab_phase=gate-l2\" \\"
  echo "    -var=\"operator_cidr=\${MY_IP}/32\" \\"
  echo "    -var=\"ami_id_override=\${AMI_ID}\" \\"
  echo "    -var=\"enable_artifact_download=true\" \\"
  echo "    -var=\"artifact_bucket=${ARTIFACT_BUCKET}\" \\"
  echo "    -var=\"enable_observer=true\" \\"
  echo "    -var=\"enable_discovery=true\" \\"
  echo "    -var=\"discovery_scope_mode=local-interfaces\""
  echo ""
  echo -e "${BOLD}Passo 2 — aguardar cloud-init (~3 min), depois atualizar inventory:${NC}"
  echo ""
  echo "  # Obter IPs públicos:"
  echo '  terraform output 2>&1 | grep public_ip'
  echo ""
  echo "  # Atualizar examples/aws-lab/ansible/inventory.local.ini com os IPs acima"
  echo ""
  echo -e "${BOLD}Passo 3 — validação Gate L.2 (ansible):${NC}"
  echo ""
  echo "  cd $PROJECT_ROOT"
  echo "  ansible-playbook -i examples/aws-lab/ansible/inventory.local.ini \\"
  echo "    examples/aws-lab/ansible/validate-gate-l2-local-interface.yml"
  echo ""
  echo -e "${BOLD}Passo 4 — destruir lab ao terminar:${NC}"
  echo ""
  echo "  cd $PROJECT_ROOT/examples/aws-lab/terraform"
  echo "  terraform destroy \\"
  echo "    -var=\"lab_phase=gate-l2\" \\"
  echo "    -var=\"operator_cidr=\${MY_IP}/32\" \\"
  echo "    -var=\"ami_id_override=\${AMI_ID}\" \\"
  echo "    -var=\"enable_artifact_download=true\" \\"
  echo "    -var=\"artifact_bucket=${ARTIFACT_BUCKET}\" \\"
  echo "    -var=\"enable_observer=true\" \\"
  echo "    -var=\"enable_discovery=true\" \\"
  echo "    -var=\"discovery_scope_mode=local-interfaces\""
  echo ""
fi

exit "$errors"

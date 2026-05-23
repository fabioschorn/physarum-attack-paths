#!/usr/bin/env bash
#
# deploy-pf1.sh — Compila physarum-maze para x86_64-unknown-linux-gnu
#                 via Docker Build Cloud e faz upload para S3.
#
# Uso:
#   ./Utilities/deploy-pf1.sh
#   ./Utilities/deploy-pf1.sh --skip-build     # pula o build (já compilado)
#   ./Utilities/deploy-pf1.sh --skip-upload    # pula o upload S3
#   ./Utilities/deploy-pf1.sh --dry-run        # mostra comandos sem executar
#
# Pré-requisitos:
#   - Docker Build Cloud configurado: docker buildx ls | grep cloud-fs09
#   - AWS CLI configurado com credenciais da conta 168740128169
#
# Resultado:
#   - Binário em target/pf1-linux-x86_64/release/physarum-maze
#   - Upload para s3://physarum-artifacts-168740128169/physarum-attack-paths/pf-1/linux-x86_64/

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

# ─── Configuração PF-1 ───────────────────────────────────────────────────────
CLOUD_BUILDER="cloud-fs09-physarum-attack-paths"
DOCKER_IMAGE="rust:1-slim-bookworm"
ARTIFACT_BUCKET="physarum-artifacts-168740128169"
ARTIFACT_PREFIX="physarum-attack-paths/pf-1/linux-x86_64"
ARTIFACT_REGION="us-east-1"
EXPECTED_ACCOUNT="168740128169"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$PROJECT_ROOT/target/pf1-linux-x86_64"
BINARIES=("physarum-maze")

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
      echo ""
      echo "  --skip-build    Não executa o build (binário já existe em target/pf1-linux-x86_64/release/)"
      echo "  --skip-upload   Não faz upload para S3 (só compila)"
      echo "  --dry-run       Mostra os comandos sem executá-los"
      exit 0
      ;;
    *)
      echo -e "${RED}Argumento desconhecido: $arg${NC}"
      echo "Use --help para ver as opções disponíveis."
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
echo -e "${BOLD}${BLUE}║    Physarum Attack Paths — Deploy PF-1 (physarum-maze)       ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Projeto        : $PROJECT_ROOT"
info "Cloud builder  : $CLOUD_BUILDER"
info "S3 bucket      : $ARTIFACT_BUCKET"
info "S3 prefix      : $ARTIFACT_PREFIX"
info "Iniciado       : $(date '+%Y-%m-%d %H:%M:%S')"
[ "$DRY_RUN" = true ]     && warn "Modo dry-run ativo — nenhum comando destrutivo será executado"
[ "$SKIP_BUILD" = true ]  && warn "Build ignorado (--skip-build)"
[ "$SKIP_UPLOAD" = true ] && warn "Upload S3 ignorado (--skip-upload)"

# ─── 1. Pré-requisitos ───────────────────────────────────────────────────────
section "1. Pré-requisitos"

if ! command -v docker &>/dev/null; then
  fail "Docker não encontrado. Instale o Docker Desktop e tente novamente."
  exit 1
fi
if ! docker info &>/dev/null; then
  fail "Docker não está em execução. Inicie o Docker Desktop e tente novamente."
  exit 1
fi
pass "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

if ! command -v aws &>/dev/null; then
  fail "AWS CLI não encontrado. Instale com: brew install awscli"
  exit 1
fi
pass "AWS CLI $(aws --version 2>&1 | awk '{print $1}')"

# ─── 2. Verificação de conta AWS ─────────────────────────────────────────────
section "2. Verificação de conta AWS"

ACTUAL_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "FALHA")

if [ "$ACTUAL_ACCOUNT" = "FALHA" ]; then
  fail "Não foi possível obter a identidade AWS. Verifique suas credenciais."
  exit 1
fi

if [ "$ACTUAL_ACCOUNT" != "$EXPECTED_ACCOUNT" ]; then
  fail "Conta incorreta: esperado $EXPECTED_ACCOUNT, encontrado $ACTUAL_ACCOUNT"
  fail "Troque de perfil AWS antes de continuar."
  exit 1
fi
pass "Conta AWS: $ACTUAL_ACCOUNT (OK)"
info "Identidade: $(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)"

# ─── 3. Verificação do bucket S3 ─────────────────────────────────────────────
section "3. Verificação do bucket S3"

if aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" --region "$ARTIFACT_REGION" &>/dev/null; then
  pass "Bucket s3://$ARTIFACT_BUCKET existe e está acessível"
else
  fail "Bucket s3://$ARTIFACT_BUCKET não encontrado ou sem permissão de acesso."
  exit 1
fi

# ─── 4. Selecionar builder ───────────────────────────────────────────────────
section "4. Selecionar builder"

BUILDER="default"
if docker buildx inspect "$CLOUD_BUILDER" &>/dev/null 2>&1; then
  BUILDER="$CLOUD_BUILDER"
  pass "Docker Build Cloud disponível: $CLOUD_BUILDER"
else
  warn "Docker Build Cloud ($CLOUD_BUILDER) não disponível — usando builder local"
fi
info "Builder selecionado: $BUILDER"

# ─── 5. Build ────────────────────────────────────────────────────────────────
section "5. Build Linux x86_64"

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
    # ── Docker Build Cloud ────────────────────────────────────────────────────
    # Inline Dockerfile: builder stage compiles, scratch export stage extracts binaries.
    info "Usando Docker Build Cloud: $BUILDER"
    info "Enviando contexto e compilando no cloud (primeira execução pode demorar)"

    TMP_DOCKERFILE=$(mktemp "${TMPDIR:-/tmp}/Dockerfile.pf1.XXXXXX")
    cat > "$TMP_DOCKERFILE" <<'DOCKERFILE_CONTENT'
FROM rust:1-slim-bookworm AS builder
RUN apt-get update -qq && apt-get install -y --no-install-recommends gcc libc6-dev
WORKDIR /workspace
COPY . .
RUN cargo build --release -p physarum-maze

FROM scratch AS export
COPY --from=builder /workspace/target/release/physarum-maze .
DOCKERFILE_CONTENT

    # .dockerignore prevents sending target/ and secrets to the cloud builder.
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
    # ── Fallback local (docker run com volume mounts) ─────────────────────────
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
        cargo build --release -p physarum-maze 2>&1
      "
    )

    if [ "$DRY_RUN" = true ]; then
      echo -e "  ${YELLOW}[DRY-RUN]${NC} ${BUILD_CMD[*]}"
    else
      if "${BUILD_CMD[@]}"; then
        pass "Build local concluído em $(elapsed "$build_start")"
      else
        fail "Build local falhou — verifique a saída acima"
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

# ─── 6. Upload para S3 ───────────────────────────────────────────────────────
section "6. Upload para S3"

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
    info "Verificando objeto enviado:"
    aws s3 ls "s3://${ARTIFACT_BUCKET}/${ARTIFACT_PREFIX}/" --region "$ARTIFACT_REGION" | \
      awk '{printf "    %s  %s  (%s bytes)\n", $1, $4, $3}'
  fi
fi

# ─── 7. Próximos passos ───────────────────────────────────────────────────────
section "7. Próximos passos"

ELAPSED_TOTAL=$(elapsed "$overall_start")

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                          Resumo                              ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
if [ "$errors" -eq 0 ]; then
  echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}✔ PF-1 deploy concluído em ${ELAPSED_TOTAL}.${NC}"
  echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}  Builder: $BUILDER${NC}"
else
  echo -e "${BOLD}${BLUE}║${NC}  ${RED}✘ $errors erro(s). Corrija acima e tente novamente.${NC}"
fi
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ "$errors" -eq 0 ]; then
  echo ""
  echo -e "${BOLD}Passo 1 — terraform apply (PF-1):${NC}"
  echo ""
  echo "  cd $PROJECT_ROOT/examples/aws-lab/terraform-pf1"
  echo ""
  echo '  MY_IP=$(curl -s https://checkip.amazonaws.com)'
  echo '  AMI_ID=$(aws ec2 describe-images \'
  echo '    --owners amazon \'
  echo '    --filters "Name=name,Values=al2023-ami-*-kernel-*-x86_64" "Name=state,Values=available" \'
  echo '    --query '"'"'sort_by(Images, &CreationDate)[-1].ImageId'"'"' \'
  echo '    --output text --region us-east-1)'
  echo ""
  echo "  terraform apply \\"
  echo '    -var operator_cidr="${MY_IP}/32" \'
  echo '    -var ami_id_override="${AMI_ID}"'
  echo ""
  echo -e "${BOLD}Passo 2 — lançar o organismo no Host A:${NC}"
  echo ""
  echo '  HOST_A_IP=<public IP do host-a>'
  echo '  IFACE=$(ssh -i examples/aws-lab/.keys/physarum-lab-devlead ec2-user@$HOST_A_IP \'
  echo '    "ip -o link show | awk -F'\'': '\'' '\''{print \$2}'\'' | grep -v lo | head -1")'
  echo '  ssh -i examples/aws-lab/.keys/physarum-lab-devlead ec2-user@$HOST_A_IP \'
  echo '    "sudo nohup /usr/local/bin/physarum-maze --mode seed --interface \$IFACE >/tmp/physarum-maze.log 2>&1 &"'
  echo ""
  echo -e "${BOLD}Passo 3 — verificar expansão (Ansible):${NC}"
  echo ""
  echo "  ansible-playbook -i examples/aws-lab/ansible/inventory.pf1.ini \\"
  echo "    examples/aws-lab/ansible/verify-maze-connectivity.yml"
  echo ""
  echo -e "${BOLD}Passo 4 — destruir lab ao terminar:${NC}"
  echo ""
  echo "  terraform destroy \\"
  echo '    -var operator_cidr="${MY_IP}/32" \'
  echo '    -var ami_id_override="${AMI_ID}"'
  echo ""
fi

exit "$errors"

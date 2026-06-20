#!/usr/bin/env bash
#
# Build and load physarum-maze:lab with traceable build identity.
#
# Optional overrides:
#   PHYSARUM_DOCKER_BUILDER  buildx builder name
#   PHYSARUM_BUILD_ID        operator/CI build identifier
#   PHYSARUM_GIT_SHA         source revision (normally detected automatically)
#   PHYSARUM_OCI_DEST        temporary OCI archive path

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="${PHYSARUM_DOCKER_BUILDER:-cloud-expertsonline-physarum-attack-paths}"
OCI_DEST="${PHYSARUM_OCI_DEST:-/tmp/physarum-maze-lab.tar}"

cd "$PROJECT_ROOT"

GIT_REVISION="${PHYSARUM_GIT_SHA:-$(git rev-parse HEAD)}"
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    GIT_REVISION="${GIT_REVISION%-dirty}-dirty"
fi

if [ -n "${PHYSARUM_BUILD_ID:-}" ]; then
    BUILD_ID="$PHYSARUM_BUILD_ID"
elif [ -n "${GITHUB_RUN_ID:-}" ]; then
    BUILD_ID="github-${GITHUB_RUN_ID}"
else
    BUILD_ID="local"
fi

echo "Building physarum-maze:lab"
echo "  commit:   ${GIT_REVISION}"
echo "  build-id: ${BUILD_ID}"
echo "  builder:  ${BUILDER}"

docker buildx build \
    --builder "$BUILDER" \
    --platform linux/amd64 \
    --tag physarum-maze:lab \
    --build-arg "PHYSARUM_GIT_SHA=${GIT_REVISION}" \
    --build-arg "PHYSARUM_BUILD_ID=${BUILD_ID}" \
    --output "type=oci,dest=${OCI_DEST}" \
    -f docker/physarum-maze-lab.Dockerfile \
    .

docker load -i "$OCI_DEST"

docker run --rm physarum-maze:lab --version

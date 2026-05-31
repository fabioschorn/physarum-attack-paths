# physarum-maze Docker Lab — source-build variant (PF-3.1 adaptive fingerprint)
#
# Two-stage build for Docker Lab validation from macOS.
# Stage 1: compiles physarum-maze from source in linux/amd64 Rust environment.
# Stage 2: packages the binary into a slim runtime image.
#
# Used by docker-compose-lab.yml for the four-container PF-3.1 validation lab:
#   host-a (this image) — physarum-maze agent with mock LLM
#   host-b              — nginx:alpine on port 80
#   host-c              — python http.server on port 8080
#   host-d              — python http.server on port 7777 (Layer 3 adaptive probe)
#
# Production releases use physarum-maze.Dockerfile (pre-compiled binary via CI).
# This Dockerfile is for lab runs only where a Linux cross-compiler is unavailable.
#
# Build (cloud builder — law):
#   docker buildx build --builder cloud-expertsonline-physarum-attack-paths \
#     --platform linux/amd64 --output type=oci,dest=/tmp/physarum-maze-lab.tar \
#     -f docker/physarum-maze-lab.Dockerfile .
#   docker load -i /tmp/physarum-maze-lab.tar

FROM rust:1.86-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only what physarum-maze and its workspace deps need
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/physarum-maze/        crates/physarum-maze/
COPY crates/physarum-llm/         crates/physarum-llm/
COPY crates/physarum-scanner/     crates/physarum-scanner/
COPY crates/physarum-sporangium/  crates/physarum-sporangium/
# Remaining workspace members — needed so Cargo resolves the workspace,
# but only stubs are required for the physarum-maze build.
COPY crates/physarum-protocol/    crates/physarum-protocol/
COPY crates/physarum-node-runtime/ crates/physarum-node-runtime/
COPY crates/physarum-probe/       crates/physarum-probe/
COPY crates/physarum-node/        crates/physarum-node/
COPY crates/physarum-server/      crates/physarum-server/
COPY crates/physarum-agent/       crates/physarum-agent/
COPY crates/physarum-ebpf-observer/ crates/physarum-ebpf-observer/
COPY crates/physarum-packet-observer/ crates/physarum-packet-observer/

RUN cargo build --release -p physarum-maze

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sshpass \
        iputils-ping \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/physarum-maze /usr/local/bin/physarum-maze
RUN chmod +x /usr/local/bin/physarum-maze

ENTRYPOINT ["physarum-maze"]

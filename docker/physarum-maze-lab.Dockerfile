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
#   ./docker/build-physarum-maze-lab.sh

FROM rust:1.86-slim-bookworm AS builder

# musl-tools: provides musl-gcc linker wrapper required by x86_64-unknown-linux-musl target.
# reqwest uses rustls-tls (pure Rust), so no OpenSSL is needed — musl compiles cleanly.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        musl-tools && \
    rustup target add x86_64-unknown-linux-musl && \
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

ARG PHYSARUM_GIT_SHA=unknown
ARG PHYSARUM_BUILD_ID=dev
ENV PHYSARUM_GIT_SHA=${PHYSARUM_GIT_SHA}
ENV PHYSARUM_BUILD_ID=${PHYSARUM_BUILD_ID}

# Static musl binary — no glibc dependency at runtime.
# Propagated agents can run on any Linux regardless of glibc version (fixes Issue #158 Bug 2).
RUN cargo build --release --target x86_64-unknown-linux-musl -p physarum-maze

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-client \
        sshpass \
        iputils-ping \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/*
# openssh-client provides: ssh, scp, ssh-keygen (ephemeral keypair generation for exploit path)

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/physarum-maze /usr/local/bin/physarum-maze
RUN chmod +x /usr/local/bin/physarum-maze

# Templates are embedded inside the binary as nuclei-templates.tar.zst (include_bytes!).
# physarum-sporangium extracts them to /tmp/physarum/templates/nuclei-legacy/ on first run.
# PHYSARUM_TEMPLATE_DIR can still override this at runtime if needed.

ENTRYPOINT ["physarum-maze"]

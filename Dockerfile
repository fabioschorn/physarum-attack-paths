# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM rust:1.86-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release -p physarum-server -p physarum-agent -p physarum-node

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:13.5-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/physarum-server /usr/local/bin/
COPY --from=builder /app/target/release/physarum-agent /usr/local/bin/
COPY --from=builder /app/target/release/physarum-node /usr/local/bin/

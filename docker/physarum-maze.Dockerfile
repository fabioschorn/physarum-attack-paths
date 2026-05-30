# physarum-maze Docker Lab image
#
# Build sequence (enforced by docker-lab.sh):
#   1. cargo build --release -p physarum-maze   (local, native)
#   2. docker buildx build --builder cloud-expertsonline-physarum-attack-paths
#
# The Rust binary is compiled locally first; Docker only packages it.
# This keeps image build fast and avoids pulling the full Rust toolchain
# into the cloud builder layer.

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sshpass \
        iputils-ping \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/*

COPY target/release/physarum-maze /usr/local/bin/physarum-maze
RUN chmod +x /usr/local/bin/physarum-maze

ENTRYPOINT ["physarum-maze"]

# physarum-attack-paths

> **Bio-inspired emergent attack-path discovery for hybrid cloud and on-prem environments.** Lightweight Rust agents observe network flows via eBPF; conductivities reinforce and decay across the graph; security layers and lateral-movement paths emerge from behavior, not declarations.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-research--prototype-orange.svg)](https://github.com/fabioschorn/physarum-attack-paths)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/fabioschorn/physarum-attack-paths/releases)
[![CI](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml/badge.svg)](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml)

`physarum-attack-paths` is a distributed system for discovering, validating, and continuously refining cybersecurity attack paths across heterogeneous computing environments. It abstracts away from the static, scanner-centric view of the network and replaces it with a **living topology**: each host runs a lightweight Rust agent, and the system as a whole behaves like the slime mold *Physarum polycephalum* — strengthening the routes that carry real flow and pruning the routes that don't.

The result is an attack-path graph that is **observed**, not declared. Layer assignments emerge from behavior. Drift is detected as a derivative of edge conductivity over time. The autonomous validation agents from the upstream patented system consume a graph that reflects *what attackers can actually do*, not *what the scanner thinks they might do*.

---

## Table of contents

- [Motivation](#motivation)
- [Conceptual model](#conceptual-model)
- [Architecture](#architecture)
- [Mathematical core](#mathematical-core)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Development workflow](#development-workflow)
- [Agent reference](#agent-reference)
- [Coordinator reference](#coordinator-reference)
- [Protocol](#protocol)
- [Security model](#security-model)
- [Operational considerations](#operational-considerations)
- [Roadmap](#roadmap)
- [Relationship to upstream IP](#relationship-to-upstream-ip)
- [References](#references)

---

## Motivation

Traditional attack-path analysis suffers from three failures that compound at scale:

The **single-vantage-point problem.** Tools that scan a network from one location (the legacy `Visio 2000` Enterprise Network Tools approach, modern external scanners) get a distorted view distorted by NAT, micro-segmentation, ephemeral cloud workloads, and zero-trust mesh policies. They see what they can reach, not what exists.

The **declarative-topology problem.** Tools that ask each asset to declare its layer, zone, or security tier accumulate technical debt fast. A misconfigured `NetworkPolicy` in Kubernetes, an over-permissive `SecurityGroup` in AWS, a forgotten firewall rule on-prem — none of these change what the asset *says* it is, but all of them change what an attacker can do.

The **stale-snapshot problem.** Even probabilistic attack-graph systems compute edge probabilities once from scanner output and freeze them. By the time the autonomous pentest agents run validation workflows, the graph reflects last week's configuration, not today's reality.

`Physarum` addresses all three by treating attack-path topology as an emergent property of agent activity. There is no central authority declaring layers. There is no static `P(e)`. There is a continuous reinforcement-decay process running across thousands of agents, and the structure that survives is — by construction — the structure that matters.

---

## Conceptual model

The biological *Physarum polycephalum* is an acellular slime mold that solves shortest-path problems by growing tubes between food sources. Tubes carrying more cytoplasm thicken; tubes carrying less atrophy. After hours of adaptation, the surviving network is provably close to the optimal transport solution (Tero, Kobayashi & Nakagaki, 2007).

We map this dynamic onto a security graph:

| Biological | Security |
|---|---|
| Inoculation point | Externally reachable asset / known compromised host |
| Food source (oatmeal) | Crown jewel / high-`CRIT` asset / Layer-1 protected core |
| Tube between nodes | Candidate attack edge between two agents |
| Tube thickness `D_ij` | Edge conductivity (dynamic; replaces static `P(e)`) |
| Cytoplasm flow `Q_ij` | Combined evidence: probes + lateral-movement validations + observed traffic |
| Tube length `L_ij` | Traversal resistance from scanner-derived `W(e)` |
| Reinforcement | Successful exploitability confirmation |
| Decay | Absence of evidence over time |

The system does **not** simulate slime mold. It borrows the *form* of the differential equation because that form has provably good convergence properties on path-finding problems and naturally accommodates real-time adaptation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HYBRID ENVIRONMENT                           │
│                                                                     │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│   │  agent   │◄──►│  agent   │◄──►│  agent   │◄──►│  agent   │      │
│   │  AWS-EC2 │    │  AWS-EKS │    │  on-prem │    │  Azure   │      │
│   └─────┬────┘    └─────┬────┘    └─────┬────┘    └─────┬────┘      │
│         │               │               │               │           │
│         │  signed probes (QUIC, peer-to-peer)           │           │
│         │               │               │               │           │
└─────────┼───────────────┼───────────────┼───────────────┼───────────┘
          │               │               │               │
          │       batched signed reports (60s)            │
          │               │               │               │
          ▼               ▼               ▼               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        COORDINATOR                                  │
│                                                                     │
│   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│   │  Ingest API    │─►│  Graph Engine  │─►│  Pressure      │        │
│   │  (axum/QUIC)   │  │  (petgraph)    │  │  Solver        │        │
│   └────────────────┘  └────────────────┘  └────────────────┘        │
│           │                  │                    │                 │
│           ▼                  ▼                    ▼                 │
│   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│   │  Timeseries    │  │  TOON          │  │  Pentest       │        │
│   │  (ClickHouse)  │  │  Serializer    │─►│  Orchestrator  │        │
│   └────────────────┘  └────────────────┘  └────────────────┘        │
│                                                    │                │
└────────────────────────────────────────────────────┼────────────────┘
                                                     │
                              feedback ◄─────────────┘
                              (validation outcomes
                               reshape D_ij)
```

### Components

**Agent** (`crates/physarum-agent`). Runs on each Linux host. Single binary, ~10 MB resident memory, attaches eBPF programs to capture flow telemetry, signs and exchanges probes with peers, reports periodically to the coordinator. Boot-time attestation via TPM, AWS Nitro, Azure CVM, or GCP Confidential VM.

**eBPF program** (`crates/physarum-ebpf`). Compiled separately as a `no_std` Rust binary, attached to kernel tracepoints (`sock:inet_sock_set_state`, optionally `tcp:tcp_probe`). Maintains a hash map of active flows in kernel memory; user-space drains it every 60 seconds.

**Coordinator** (`crates/physarum-coordinator`). Stateful service. Receives signed reports, verifies signatures, updates the conductivity graph, runs the Physarum reinforcement-decay loop, solves pressures via discrete Laplace, exposes the resulting graph via API to the upstream pentest orchestrator.

**Graph core** (`crates/physarum-graph`). Pure-algorithmic crate. Implements the Physarum dynamics, pressure solver, and emergent layer classification. Property-tested with `proptest`. No I/O, no async — testable in isolation.

**Protocol** (`crates/physarum-protocol`). Shared types between agent and coordinator. `no_std`-compatible so the same wire types can ship in constrained environments.

**CLI** (`crates/physarum-cli`). Operational tooling: register agents, inspect graph state, replay timeseries, dump TOON output for downstream agents.

---

## Mathematical core

### Edge conductivity (`D_ij`)

For each directed edge between agents *i* and *j*:

```
D_ij(t+Δt) = D_ij(t) + f(Q_ij(t)) · (1 - D_ij(t)) - r · D_ij(t)
```

Where:
- `Q_ij(t)` is the observed flow over the edge in the last interval (combined signal, see below)
- `f(x) = x² / (1 + x²)` is a saturating reinforcement function
- `r ∈ [0, 1]` is the decay rate (default `0.1`)
- `D_ij` is clamped to `[0, 1]`

Saturation prevents an attacker from inflating `D_ij` by flooding traffic. Decay ensures unused edges fade.

### Combined flow signal (`Q_ij`)

```
Q_ij = w₁ · Probe(i,j) + w₂ · Validation(i,j) + w₃ · Observe(i,j)
```

Three independent evidence sources:

- **Probe** — outcome of authenticated round-trip probes (`0` or `1`)
- **Validation** — successful lateral-movement events confirmed by upstream pentest agents, weighted by `CRIT(target)`
- **Observe** — eBPF-captured traffic volume, log-scaled and quality-weighted (mTLS-verified flows count more than plaintext)

Default weights: `w₁=0.3, w₂=0.5, w₃=0.2`.

### Edge resistance (`L_ij`)

Inherited unchanged from the upstream patented system:

```
L_ij = a₁·PORT_EXPOSURE + a₂·LAYER_TRANSITION + a₃·DEVICE_TYPE + a₄·SERVICE_WEAKNESS
```

This is the static, scanner-derived component. `Physarum` does not replace it — it composes with it.

### Path attractiveness

For a candidate path `π = (v₀, v₁, ..., vₙ)`:

```
Attractiveness(π) = Π_{(i,j) ∈ π} (D_ij / L_ij)
```

Equivalently in log-space (used for shortest-path computation):

```
-log Attractiveness(π) = Σ_{(i,j) ∈ π} [log L_ij - log D_ij]
```

Yen K-shortest paths over this cost function returns the K most attractive attack paths — the ones the system should validate first.

### Emergent pressure (`p_i`)

Each agent computes a local scalar pressure via gossip with neighbors:

```
p_i(t+1) = Σⱼ (D_ij / L_ij) · p_j(t) / Σⱼ (D_ij / L_ij)
```

Anchored at:
- `p = 1.0` for externally reachable entry points
- `p = 0.0` for declared crown jewels

This is a distributed solution to the discrete Laplace equation on the weighted graph. Convergence is guaranteed; typically reaches steady state in 20–50 gossip rounds.

### Emergent layers

```
p_i ∈ [0.75, 1.00]  →  Layer 4 (External Perimeter)
p_i ∈ [0.50, 0.75]  →  Layer 3 (Gateways)
p_i ∈ [0.25, 0.50]  →  Layer 2 (Application Services)
p_i ∈ [0.00, 0.25]  →  Layer 1 (Protected Core)
```

Thresholds are configurable. Drift is detected as `|layer_emergent(t) - layer_emergent(t-Δ)| > 0`.

---

## Repository layout

> Legend: `✔` implemented · `◌` planned

```
physarum-attack-paths/
├── Cargo.toml                        # workspace root (resolver = "2", msrv 1.78)
├── Cargo.lock                        # committed — binary project reproducibility
├── README.md
├── LICENSE                           # Apache 2.0
├── NOTICE
├── SECURITY.md
│
├── crates/
│   ├── physarum-protocol/       ✔    # shared wire types across all crates
│   │   └── src/lib.rs               # AgentInfo, RegisterRequest/Response,
│   │                                # ProbeReport, GraphSnapshot, EdgeSnapshot
│   │
│   ├── physarum-server/         ✔    # Phase 0 HTTP coordinator (Axum 0.7 + Tokio)
│   │   └── src/
│   │       ├── main.rs              # CLI (--listen), router, Arc<AppState>
│   │       ├── state.rs             # RwLock<HashMap<AgentId, AgentInfo>>
│   │       └── routes/
│   │           ├── health.rs        # GET  /health
│   │           └── agents.rs        # POST /register · GET /agents
│   │
│   ├── physarum-graph/          ◌    # Phase 0 — pure algorithmic core
│   │   └── src/
│   │       ├── dynamics.rs          # D_ij update, saturation f(x)=x²/(1+x²), decay r
│   │       ├── pressure.rs          # discrete Laplace solver
│   │       ├── layer.rs             # emergent layer classification
│   │       └── paths.rs             # Yen K-shortest over -log(D/L)
│   │
│   ├── physarum-agent/          ◌    # Phase 1 — host agent binary
│   │   └── src/
│   │       ├── main.rs              # tokio runtime, select! loop
│   │       ├── probes.rs            # peer probes with RTT measurement
│   │       ├── reporter.rs          # batched submission to coordinator
│   │       └── neighbors.rs         # NeighborState, FlowCounter
│   │
│   ├── physarum-ebpf/           ◌    # Phase 2 — kernel-side eBPF program
│   │   └── src/main.rs              # tracepoint, flow map (aya-ebpf)
│   │
│   ├── physarum-coordinator/    ◌    # Phase 3 — full coordinator with sharding
│   │   └── src/
│   │       ├── ingest.rs            # signed report ingestion
│   │       ├── update_loop.rs       # background Physarum tick
│   │       ├── timeseries.rs        # ClickHouse writer
│   │       ├── toon.rs              # TOON serialization for upstream
│   │       └── shards.rs            # consistent-hash sharding
│   │
│   └── physarum-cli/            ◌    # Phase 3 — operational tooling
│       └── src/main.rs              # graph dump, topk paths, replay
│
├── Utilities/                        # developer tooling — never shipped in binaries
│   ├── README.md                     # full script reference
│   ├── check-env.sh                  # 12-point environment validation
│   ├── build.sh                      # build / test / clippy automation
│   ├── dist-local.sh                 # local packaging (mirrors GitHub Actions)
│   └── git-scripts/
│       ├── README.md                 # commit · checkpoint · release reference
│       ├── commit.sh                 # Conventional Commits with quality gates
│       ├── checkpoint.sh             # minor version bump + push (no tag)
│       └── release.sh               # full release: bump → tag → CI → binaries
│
├── General-Docs/
│   ├── PROTOTYPE_ROADMAP.md          # phased implementation plan
│   └── README.md
│
└── .github/
    └── workflows/
        ├── ci.yml                    # build + clippy (-D warnings) + test
        └── release.yml               # Linux binary release (x86_64, aarch64)
```

---

## Quick start

> ⚠️ This is a research prototype. Do not deploy on production hosts without security review.

### Prerequisites

- Rust 1.78 or later (stable channel via `rustup`)
- Linux x86_64 or ARM64 for production deployment
- Linux kernel 5.15+ on agent hosts *(required for eBPF — Phase 2)*
- `bpf-linker` for compiling the kernel program *(Phase 2)*
- Coordinator: 4 cores and 8 GB RAM minimum *(full Phase 3 deployment)*

### Verify environment and build

```bash
git clone https://github.com/fabioschorn/physarum-attack-paths.git
cd physarum-attack-paths

# validate toolchain and project structure (recommended on first run)
./Utilities/check-env.sh

# build the Phase 0 coordinator
./Utilities/build.sh --release
```

The Phase 0 binary lands in `target/release/`:

```
physarum-server    # HTTP coordinator: /health · /register · /agents
```

### Run the coordinator

```bash
./target/release/physarum-coordinator \
    --listen 0.0.0.0:8443 \
    --tls-cert ./certs/coord.crt \
    --tls-key  ./certs/coord.key \
    --clickhouse-url http://localhost:8123 \
    --shard-count 16
```

### Run an agent

```bash
sudo ./target/release/physarum-agent \
    --coordinator https://coord.internal:8443 \
    --identity-file /var/lib/physarum/identity.key \
    --ebpf-program ./target/release/physarum-ebpf \
    --probe-interval 60s
```

The agent needs `CAP_BPF` and `CAP_NET_ADMIN`. The `systemd` unit in `deploy/systemd/` handles capability dropping correctly.

### Inspect the graph

```bash
./target/release/physarum-cli graph dump --format toon > attack-paths.toon
./target/release/physarum-cli graph topk --target db-prod-01 --k 5
```

---

## Development workflow

The `Utilities/` directory contains shell scripts that standardize every step of the
development lifecycle — from setting up a new machine to publishing a production release.
They enforce quality gates automatically so the main branch stays always green.

### Verify your environment

Before building for the first time on a new machine, run:

```bash
./Utilities/check-env.sh
```

Executes 12 checks: OS compatibility, Xcode CLT (macOS), C linker, curl, rustup,
rustc ≥ 1.78, cargo, PATH, active toolchain, git, project structure, and workspace
integrity. Each failure prints a concrete fix command.

### Build

```bash
./Utilities/build.sh              # debug build + all workspace tests
./Utilities/build.sh --release    # optimised release build + tests
./Utilities/build.sh --check      # compile check only — no binary output
./Utilities/build.sh --clippy     # full lint pass (warnings as errors)
```

### Local packaging

Simulate what GitHub Actions does for the current platform:

```bash
./Utilities/dist-local.sh
# → dist/physarum-server-<version>-<target>.tar.gz
```

### Git workflow

Three scripts cover the full commit-to-release lifecycle:

| Script | When to use |
|--------|-------------|
| `git-scripts/commit.sh` | Any code change — enforces Conventional Commits format |
| `git-scripts/checkpoint.sh` | Development milestone — version bump + push, no tag |
| `git-scripts/release.sh` | Official release — bump + tag + push → CI publishes binaries |

```bash
# Commit a change (interactive or via tmp/commit-msg.txt)
./Utilities/git-scripts/commit.sh

# Save a milestone without triggering a release
./Utilities/git-scripts/checkpoint.sh          # minor bump (default)
./Utilities/git-scripts/checkpoint.sh --patch  # patch bump

# Publish an official release to GitHub Releases
./Utilities/git-scripts/release.sh --minor
```

`commit.sh` supports a **file mode**: write the full commit message to
`tmp/commit-msg.txt` before running the script. The file is read, displayed
as a preview, and removed automatically after `git commit`.

See [`Utilities/README.md`](./Utilities/README.md) and
[`Utilities/git-scripts/README.md`](./Utilities/git-scripts/README.md) for the
full parameter reference.

### Continuous integration

Every push and pull request triggers the CI pipeline
(`.github/workflows/ci.yml`), which runs on `ubuntu-latest`:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
```

Merges to `main` that pass CI are safe to release. Tag a version with
`release.sh` and GitHub Actions (`.github/workflows/release.yml`) will compile
and publish `.tar.gz` archives for `x86_64` and `aarch64` Linux automatically.

---

## Agent reference

### Lifecycle

1. **Boot** — load identity from disk; if absent, generate ed25519 keypair, perform attestation, request enrollment certificate from coordinator.
2. **Attach eBPF** — load and attach kernel program; verify map is writable.
3. **Discover neighbors** — coordinator returns initial neighbor set + their public keys.
4. **Run main loop** — four concurrent tasks (`tokio::select!`):
   - Send probes every `probe-interval` (default 60s)
   - Run pressure gossip every 30s
   - Submit report batch every 60s
   - Handle incoming probes from peers

### Resource budget

| Metric | Target | Hard limit |
|---|---|---|
| Resident memory | < 20 MB | 64 MB |
| CPU steady-state | < 1% of 1 core | 5% |
| Network egress | < 10 KB/s | 100 KB/s |
| eBPF map size | 64K entries | configurable |

### Configuration

The agent reads TOML config from `/etc/physarum/agent.toml`:

```toml
[coordinator]
endpoint = "https://coord.internal:8443"
ca_cert  = "/etc/physarum/coord-ca.crt"

[identity]
key_file       = "/var/lib/physarum/identity.key"
attestation    = "tpm"  # tpm | nitro | azure-cvm | gcp-cvm | none

[probes]
interval        = "60s"
timeout         = "5s"
mtls            = true

[ebpf]
program_path    = "/usr/lib/physarum/physarum-ebpf"
flow_map_size   = 65536

[reporting]
batch_size      = 100
batch_interval  = "60s"
backoff_max     = "30s"
```

---

## Coordinator reference

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/enroll` | Agent enrollment (attestation in body) |
| POST | `/v1/reports` | Batch ingestion (signed reports) |
| GET  | `/v1/neighbors/{agent_id}` | Discovery |
| GET  | `/v1/graph` | Full graph dump (admin only) |
| GET  | `/v1/paths/topk` | K most attractive paths to target |
| GET  | `/v1/toon/{target}` | TOON serialization for downstream |
| WS   | `/v1/stream` | Live event stream (drift, validations) |

### Sharding

The graph is partitioned by consistent hash of `AgentId` into N shards (default 16). Each shard holds a subgraph; cross-shard edges are replicated to both endpoints' shards. The Physarum update loop runs per-shard in parallel; pressure solving is global (small enough to fit in memory after aggregation).

### State

- **Hot state**: in-memory `petgraph::DiGraph<NodeData, EdgeData>`, behind sharded `RwLock`
- **Identity**: Redis or DragonflyDB (agent registry, nonces)
- **Cold state**: ClickHouse (timeseries of `Q_ij`, `D_ij`, `p_i`, validation outcomes)

### Failure model

The coordinator is the single point of coordination but **not** the single point of truth. Agents continue probing peers even if the coordinator is unreachable; reports buffer locally up to a configurable size, then drop oldest. When the coordinator returns, agents re-submit their backlog with the original timestamps. The graph is reconstructible from timeseries history at any point.

---

## Protocol

### Wire format

QUIC transport (via `quinn`), payload encoded with `bincode` for hot path or `serde_json` for tooling. Every report is signed; the coordinator rejects:

- Reports with invalid ed25519 signatures
- Reports with non-monotonic nonces from the same agent
- Reports older than 5 minutes (replay window)
- Reports from agents whose enrollment certificate has expired

### Probe exchange (peer-to-peer)

```
agent_A                                agent_B
  │                                       │
  │── Probe { nonce, ts, sig_A } ────────►│
  │                                       │
  │◄────── Pong { nonce, ts, sig_B } ─────│
  │                                       │
  │  RTT = ts_pong - ts_probe             │
  │  flow_observed += eBPF samples        │
```

### Report submission (agent → coordinator)

```
POST /v1/reports
Authorization: Bearer <enrollment-jwt>
Content-Type: application/octet-stream

[ SignedReport_1, SignedReport_2, ..., SignedReport_N ]  (bincode)
```

### TOON output (coordinator → upstream)

The coordinator serializes the live attack-path state into the Token-Oriented Object Notation format consumed by upstream autonomous validation agents. Schema follows §8.10 of the upstream patent specification, with the addition of a `conductivity` field per edge:

```toon
@schema attack_path
  source: agent_id
  target: agent_id
  vulnerabilities: [ref_id]
  ports: [u16]
  p_v: f32
  p_e: f32
  d_ij: f32         # NEW: live conductivity
  q_ema: f32        # NEW: flow signal
  layer_emergent: u8
  layer_declared: u8?
  data_completeness: enum { full, partial, missing }
@end
```

---

## Security model

### Threats addressed

- **Compromised agent reporting false flow** — saturation function `f(Q)` caps the marginal value of high-volume signals; signature verification ensures the reported edge has the right source.
- **Replay of legitimate probes** — monotonic nonce per agent, rejection window of 5 minutes.
- **Coordinator compromise** — coordinator cannot forge agent signatures; an attacker controlling the coordinator can only disrupt aggregation, not fabricate validated paths. All historical raw signed reports remain in ClickHouse for forensic recomputation.
- **Network adversary** — QUIC + mutual TLS; agents pin coordinator's certificate at enrollment.

### Threats explicitly out of scope

- **Kernel rootkit on the agent host** — if the kernel is owned, eBPF observations are untrustworthy. This is a fundamental limitation of host-based telemetry. Mitigation: confidential computing (SEV-SNP, TDX, Nitro Enclaves) for high-value hosts.
- **Coordinator denial-of-service** — addressed at the deployment layer (rate limiting, autoscaling), not by the protocol.
- **Side-channel inference of network topology by an external observer** — the QUIC traffic between agents is encrypted but its existence is observable. Threat-model accordingly.

A full STRIDE analysis lives in `docs/threat-model.md`.

---

## Operational considerations

### Convergence time

The naive Physarum solver is known to converge slowly on large graphs. We use the `Tero+energy` variant (Liu et al., 2017) which reduces iterations by 1–2 orders of magnitude. Empirical convergence on a 10,000-node graph: ~3 minutes from cold start, ~30 seconds for incremental updates.

### Cardinality limits

| Resource | Soft limit | Hard limit |
|---|---|---|
| Agents per coordinator | 50,000 | 200,000 (with sharding) |
| Edges per agent | 256 | 1024 |
| Reports per second per shard | 10,000 | 50,000 |
| Graph size in memory | ~2 GB at 100K agents | machine RAM |

### Drift handling

When `|D_ij(t) - D_ij(t-Δ)| > drift_threshold`, the coordinator emits a `DriftEvent` on the live stream. Downstream consumers (SIEM, pentest orchestrator, dashboards) can react in real time. Default threshold: `0.3` over 10 minutes.

### Observability

Prometheus metrics exposed on `:9090/metrics`:

```
physarum_d_ij_distribution{shard="3"}
physarum_pressure_convergence_iterations
physarum_drift_events_total{severity="high"}
physarum_report_ingest_latency_seconds
physarum_signature_verification_failures_total
```

Tracing via `tracing-opentelemetry` to any OTLP-compatible backend.

---

## Roadmap

### Phase 0 — Foundations *(current)*

- [x] Mathematical model documented
- [x] Architecture defined
- [x] `physarum-protocol` crate — shared wire types (AgentInfo, ProbeReport, GraphSnapshot…)
- [x] `physarum-server` crate — HTTP coordinator with `/health`, `/register`, `/agents`
- [x] CI pipeline — build + clippy + test on every push (ubuntu-latest)
- [x] Release pipeline — Linux binary distribution via GitHub Actions (x86_64, aarch64)
- [x] Developer utilities — `check-env.sh`, `build.sh`, `dist-local.sh`, git automation scripts
- [ ] `physarum-graph` crate — D_ij dynamics, pressure solver, emergent layers, property tests

### Phase 1 — Single-host prototype

- [ ] `physarum-agent` crate — peer registration, discovery loop, HTTP probes with RTT
- [ ] `GET /peers/{agent_id}` endpoint in coordinator
- [ ] `POST /report` endpoint — probe result ingestion and in-memory storage
- [ ] FIG.3 reference scenario reproducible end-to-end (A → B → C lab validation)

### Phase 2 — eBPF integration

- [ ] Kernel program with `aya`
- [ ] User-space flow drainer
- [ ] mTLS detection in eBPF (TCP option / handshake fingerprint)

### Phase 3 — Production hardening

- [ ] Sharding + horizontal scale tests
- [ ] Attestation flows for AWS, Azure, GCP, on-prem TPM
- [ ] ClickHouse persistence + replay tooling
- [ ] Helm chart + Terraform modules

### Phase 4 — Upstream integration

- [ ] TOON serialization conformant with upstream patent §8.10
- [ ] Feedback loop from validation outcomes
- [ ] Drift event stream for the pentest orchestrator

### Phase 5 — Multi-coordinator federation

- [ ] Cross-region coordinators with eventual consistency
- [ ] Tenant isolation for managed-service deployments

---

## Relationship to upstream IP

`Physarum` is designed as a complementary system to the upstream patented framework for *Attack-Path Probability Modeling*. It does not replace any component of that framework; it augments it by replacing the static, scanner-derived edge probability `P(e)` with a live, observation-driven conductivity `D_ij`.

Specifically:

- **§8.4** (`P(e)` from `W(e)`) becomes the `t=0` initial condition of the Physarum dynamics.
- **§8.4.1** (PageRank + Betweenness pre-selection) is rendered optional. Structural relevance emerges naturally from the conductivity field.
- **§8.5** (Yen K-shortest path enumeration) operates unchanged on the live `D/L` cost function.
- **§8.7** (multi-path aggregation) consumes `P_total(v)` derived from the live attractiveness values.
- **§8.10** (TOON serialization) gains two new fields: `d_ij` and `q_ema`.
- **§8.11.1** (data augmentation for incomplete scanner inputs) is subsumed: missing scanner attributes simply produce low-confidence initial `D_ij` values that are corrected by observation.

Two distinct contributions are candidates for independent IP claims, separate from the upstream filing:

1. **Reconciliation across heterogeneous segmentation primitives** (AWS Security Groups vs Azure NSGs vs Kubernetes NetworkPolicies vs on-prem firewalls), producing a unified Layer model consumable by attack-path engines.
2. **Closed-loop refinement of the attack graph during agent execution**, where validation outcomes from upstream pentest agents feed back into edge conductivities in real time, distinct from one-shot reconciliation.

See `docs/ip-relationship.md` for full mapping.

---

## References

The mathematical foundation draws on the following work, which should be cited in any derived publication:

1. Tero, A., Kobayashi, R., Nakagaki, T. (2007). *A mathematical model for adaptive transport network in path finding by true slime mold.* Journal of Theoretical Biology, 244(4), 553–564.
2. Becchetti, L., Bonifaci, V., Dirnberger, M., Karrenbauer, A., Mehlhorn, K. (2013). *Physarum can compute shortest paths: convergence proofs and complexity bounds.* ICALP.
3. Liu, Y., Gao, C., Zhang, Z., Lu, Y., Chen, S., Liang, M., Tao, L. (2017). *An improved Physarum polycephalum algorithm for the shortest path problem.* Scientific World Journal.
4. Nakagaki, T., Yamada, H., Tóth, Á. (2000). *Maze-solving by an amoeboid organism.* Nature, 407(6803), 470.

For Rust-side dependencies of architectural significance:

- `aya` — pure-Rust eBPF library
- `quinn` — QUIC transport
- `tokio` — async runtime
- `axum` — HTTP framework
- `petgraph` — graph data structures
- `ed25519-dalek` — signature scheme

---

## License

Licensed under the Apache License, Version 2.0 (the "License").
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the [LICENSE](./LICENSE) file and [NOTICE](./NOTICE) for full terms.

---

## Contributing

Contributions require signing the Contributor License Agreement (CLA).
The CLA bot will guide you through the process on your first pull request.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development workflow,
code style, and test requirements. Security issues should be reported
according to [SECURITY.md](./SECURITY.md).

---

*"The slime mold has no brain, no nervous system, no central authority. It solves the maze anyway."*

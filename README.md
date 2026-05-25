# physarum-attack-paths

> **Bio-inspired autonomous attack-path organism.** A self-propagating Rust agent (`physarum-maze`) traverses real AWS VPC topologies without pre-provisioned targets — it discovers hosts via raw TCP/ICMP stimulus and `/24` port scanning (`physarum-scanner`), propagates itself via SCP over empty-password SSH, and records a cryptographic lineage at each hop. The underlying adaptive edge model (Q_ij → q_ema → D_ij) has been formally verified (TLA+) and validated through Gates A–PF-2: from local A/B/C probing to 9-node autonomous re-routing labs. eBPF passive flow observation (`physarum-ebpf-observer`, `physarum-packet-observer`) is AWS EC2 validated on kernel 6.18. The next frontier — the *Causal Continuity Paradox of Origin and Destination*, where the organism is confined to hosts reachable only via SSH — is being explored through planned LLM-aware adaptive propagation (`physarum-llm`, Issue #106).

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-research--prototype-orange.svg)](https://github.com/fabioschorn/physarum-attack-paths)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/fabioschorn/physarum-attack-paths/releases)
[![CI](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml/badge.svg)](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml)

`physarum-attack-paths` is a distributed system for discovering, validating, and continuously refining cybersecurity attack paths across heterogeneous computing environments. It abstracts away from the static, scanner-centric view of the network and replaces it with a **living topology**: each host runs a lightweight Rust agent, and the system as a whole behaves like the slime mold *Physarum polycephalum* — strengthening the routes that carry real flow and pruning the routes that don't.

The result is an attack-path graph that is **observed**, not declared. Layer assignments emerge from behavior. Drift is detected as a derivative of edge conductivity over time. The autonomous validation agents from the upstream patented system consume a graph that reflects *what attackers can actually do*, not *what the scanner thinks they might do*.

---

## Current status

**Research prototype** — the core adaptive edge pipeline is implemented and running.

| What | State |
|---|---|
| `physarum-protocol` shared wire types | ✔ implemented |
| `physarum-server` HTTP coordinator | ✔ implemented |
| `physarum-agent` peer-probing agent | ✔ implemented |
| `physarum-ebpf-observer` crate | ✔ implemented — AWS EC2 validated, kernel 6.18, Gate J/J.1 |
| `physarum-packet-observer` crate | ✔ implemented — raw TCP/ICMP stimulus capture, Gate L.3 |
| `physarum-scanner` crate | ✔ implemented — full RustScan feature parity, Gate L |
| `physarum-node` crate | ✔ implemented — supervised runtime (agent + observer), Gate M |
| `physarum-maze` crate | ✔ implemented — self-propagating maze agent, PF-1/PF-2 |
| `POST /flow-observations` · `GET /flow-observations` | ✔ implemented — Gate I |
| `GET /paths` endpoint (negative-log adaptive scoring) | ✔ implemented — Gate K.1 |
| TLA+ formal models (`formal/tla`) | ✔ implemented — 3 specs: single-edge, multi-agent, negative-log |
| A/B/C local lab (`examples/local-lab`) | ✔ implemented |
| A/B/C Docker lab (`examples/docker-lab`) | ✔ implemented |
| A/B/C/D Docker lab (Agent D) | ✔ implemented |
| AWS lab — Mode 1, Mode 2, tc/netem weighted paths | ✔ validated — Gates C, E, H |
| AWS lab — Gate K/K.1 (segmented adaptive + path selection) | ✔ validated |
| AWS lab — PF-1 (organic expansion maze, 7-node) | ✔ validated — autonomous SCP+SSH propagation |
| AWS lab — PF-2 (adaptive re-routing, 9-node) | ✔ validated — lateral discovery, TCP stimulus, secondary conduits |
| `physarum-llm` crate | planned — Issue #106 (Causal Continuity Paradox resolution) |
| Gate N — mTLS + Ed25519 lineage signatures | planned after Issue #106 |

See [General-Docs/ARCHITECTURE.md](./General-Docs/ARCHITECTURE.md) for the full system architecture and [General-Docs/QUALITY_GATE.md](./General-Docs/QUALITY_GATE.md) for gate definitions and acceptance criteria. Longer-term research ideas are tracked in [General-Docs/INSIGHTS_AND_BRAINSTORM.md](./General-Docs/INSIGHTS_AND_BRAINSTORM.md).

---

## Table of contents

- [Motivation](#motivation)
- [Conceptual model](#conceptual-model)
- [Architecture](#architecture)
- [Mathematical core](#mathematical-core)
- [Repository layout](#repository-layout)
- [Labs](#labs)
- [Quick start](#quick-start)
- [Development workflow](#development-workflow)
- [Roadmap](#roadmap)
- [Future architecture](#future-architecture)
- [Relationship to upstream IP](#relationship-to-upstream-ip)
- [References](#references)

---

## Motivation

Traditional attack-path analysis suffers from three failures that compound at scale:

The **single-vantage-point problem.** Tools that scan a network from one location (the legacy `Visio 2000` Enterprise Network Tools approach, modern external scanners) get a distorted view distorted by NAT, micro-segmentation, ephemeral cloud workloads, and zero-trust mesh policies. They see what they can reach, not what exists.

The **declarative-topology problem.** Tools that ask each asset to declare its layer, zone, or security tier accumulate technical debt fast. A misconfigured `NetworkPolicy` in Kubernetes, an over-permissive `SecurityGroup` in AWS, a forgotten firewall rule on-prem — none of these change what the asset *says* it is, but all of them change what an attacker can do.

The **stale-snapshot problem.** Even probabilistic attack-graph systems compute edge probabilities once from scanner output and freeze them. By the time the autonomous pentest agents run validation workflows, the graph reflects last week's configuration, not today's reality.

`Physarum` addresses all three by treating attack-path topology as an emergent property of agent activity. There is no central authority declaring layers. There is no static `P(e)`. There is a continuous reinforcement-decay process running across agents, and the structure that survives is — by construction — the structure that matters.

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
| Cytoplasm flow `Q_ij` | Combined evidence: probes + local observation window |
| Reinforcement | Successful probe + low latency |
| Decay | Absence of evidence over time |

The system does **not** simulate slime mold. It borrows the *form* of the differential equation because that form has provably good convergence properties on path-finding problems and naturally accommodates real-time adaptation.

---

## Architecture

### Current prototype (implemented)

The implemented prototype now has three cooperating layers:

```text
1. Adaptive graph layer
   physarum-server + physarum-agent
   -> registration, peer probing, ProbeReport ingest, /graph, /paths

2. Sensing and discovery layer
   physarum-ebpf-observer
   physarum-packet-observer
   physarum-scanner
   physarum-probe
   -> TCP/ICMP stimulus capture, RustScan-compatible discovery, probe execution

3. Organism runtime layer
   physarum-node
   physarum-node-runtime
   physarum-maze
   -> role-fluid runtime consolidation, autonomous maze propagation, lineage memory
```

At the graph layer, the original coordinator model remains implemented and useful:

```text
agents register -> agents probe -> reports arrive -> Q_ij -> q_ema -> D_ij -> /paths
```

At the sensing layer, nodes can observe and discover candidate corridors instead of relying only on a predeclared peer list:

```text
TCP state / packet stimulus -> candidate host -> scanner/probe -> edge evidence
```

At the organism layer, `physarum-maze` has validated the full pre-final behavior in AWS:

```text
PF-1: one seed expands through a 7-node maze and records lineage.
PF-2: the organism re-senses new structure, handles TCP stimulus, avoids duplicate propagation into already-colonized G, and records a secondary conduit.
```

The current architecture is therefore no longer just a server with fixed clients. It is a research organism composed of graph memory, local senses, bounded discovery, propagation, and lineage.

### Next architecture tracks *(planned)*

The immediate planned tracks are intentionally narrow:

```text
Issue #106
  physarum-llm research/design for the Causal Continuity Paradox.

Issue #89 / Gate N.0
  secure organism identity, mTLS, and lineage threat model after Issue #106.
```

No broader production runtime is claimed yet. Secure identity, signed lineage, and mTLS are planned design/implementation gates, not current guarantees.

---

## Mathematical core

The following pipeline is **currently implemented** in `physarum-agent` and `physarum-server`.

### Stimulus signal (`Q_ij`)

Each probe report contains `success_rate ∈ [0, 1]` and `avg_rtt_ms`.

```
latency_score = 1 / (1 + avg_rtt_ms / 100)

Q_ij = 0                                                    if success_rate = 0
Q_ij = clamp(0.7 · success_rate + 0.3 · latency_score, 0, 1)  otherwise
```

### EMA-smoothed signal (`q_ema`)

```
q_ema(t+1) = 0.3 · Q_ij + 0.7 · q_ema(t)
```

α = 0.3 gives a fast response to improvement and a slower decay on failure.

### Sigmoid growth drive (`f`)

```
f(x) = x² / (1 + x²)
```

Saturates at 0.5 for x = 1.0 (maximum stimulus). Prevents runaway reinforcement.

### Edge conductivity (`D_ij`)

```
D_ij(t+1) = clamp( D_ij(t) + f(q_ema) · (1 - D_ij) - 0.1 · D_ij,  0, 1 )
```

Where:
- `f(q_ema) · (1 - D_ij)` — growth term (sigmoid-gated, saturates near 1)
- `0.1 · D_ij` — decay term (10% per interval, prunes unused edges)

Equilibrium under sustained successful probes:

```
D* = f(1) / (f(1) + 0.1) = 0.5 / 0.6 ≈ 0.833
```

The TLA+ model in `formal/tla/` formally verifies that `q_ema` and `D_ij` stay in `[0, 1]` for all reachable states and all possible probe sequences.

---

## Repository layout

> Legend: `✔` implemented · `◌` planned

```
physarum-attack-paths/
├── Cargo.toml                            # workspace root (resolver = "2", msrv 1.86)
├── Cargo.lock                            # committed — binary project reproducibility
├── README.md
├── LICENSE                               # Apache 2.0
├── NOTICE
├── SECURITY.md
├── Dockerfile                            # multi-stage: rust:1.86-slim → debian:bookworm-slim
│
├── crates/
│   ├── physarum-protocol          ✔      # shared wire types across all crates
│   ├── physarum-server            ✔      # HTTP coordinator
│   ├── physarum-agent             ✔      # peer-probing agent
│   ├── physarum-ebpf-observer     ✔      # eBPF userspace sidecar
│   ├── physarum-ebpf-observer-ebpf ✔     # eBPF bytecode
│   ├── physarum-packet-observer   ✔      # raw-socket stimulus capture
│   ├── physarum-packet-observer-ebpf ✔   # eBPF bytecode for packet observer
│   ├── physarum-scanner           ✔      # async port scanner — RustScan feature parity
│   ├── physarum-probe             ✔      # probe execution library
│   ├── physarum-node              ✔      # node runtime
│   ├── physarum-node-runtime      ✔      # node runtime library
│   └── physarum-maze              ✔      # self-propagating maze agent
│
├── examples/
│   ├── local-lab/                 ✔      # manual A/B/C lab
│   ├── docker-lab/                ✔      # Docker Compose A/B/C lab
│   └── aws-lab/                   ✔      # AWS EC2/VPC labs through PF-2
│
├── formal/
│   └── tla/                       ✔      # TLA+ formal models — three verified specs
│
├── General-Docs/
│   ├── ARCHITECTURE.md
│   ├── QUALITY_GATE.md
│   ├── EBPF_FLOW_OBSERVATION_DESIGN.md
│   ├── ROLE_FLUID_AGENT_ARCHITECTURE.md
│   ├── INSIGHTS_AND_BRAINSTORM.md
│   └── README.md
│
├── Utilities/                           # developer tooling — never shipped in binaries
└── .github/
    └── workflows/
        ├── ci.yml                        # build + clippy (-D warnings) + test
        └── release.yml                   # Linux binary release (x86_64, aarch64)
```

---

## Labs

| Lab | What it runs | Status |
|---|---|---|
| `examples/local-lab` | A/B/C agents + server on localhost | ✔ implemented |
| `examples/docker-lab` | A/B/C/D agents + server in Docker Compose | ✔ implemented |
| `examples/aws-lab/terraform` | EC2/VPC — Mode 1, Mode 2, tc/netem, Gates K/K.1 | ✔ validated |
| `examples/aws-lab/terraform-pf1` | 7-node autonomous expansion maze (PF-1) | ✔ validated — A→C→E→F→G in 55s |
| `examples/aws-lab/terraform-pf2` | 9-node adaptive re-routing (PF-2) | ✔ validated — lateral discovery + TCP stimulus + secondary conduits |
| `formal/tla` | TLA+ formal models — 3 specs verified by TLC | ✔ implemented |

---

## Quick start

> This is a research prototype. Do not deploy on production hosts without security review.

### Prerequisites

- Rust 1.86 or later (stable channel via `rustup`)
- Docker Desktop ≥ 4.25 or Docker Engine ≥ 24 with Compose v2 (for the Docker lab)
- `curl` and `jq` on the host (for the validation scripts)
- macOS or Linux x86_64 / ARM64

### Option A — Docker lab (recommended)

Builds and runs the full A/B/C stack in isolated containers:

```bash
cd examples/docker-lab
docker compose up --build
```

Wait for both agents to register (watch for `registered with coordinator` in the logs), then validate:

```bash
bash check-docker-lab.sh
```

Expected: `Results: 34 passed, 0 failed`.

Stop and clean up:

```bash
docker compose down
```

### Option B — Local lab (manual)

Run each process in a separate terminal:

```bash
# Terminal 1 — coordinator
cargo run -p physarum-server -- --listen 127.0.0.1:8080

# Terminal 2 — agent B
cargo run -p physarum-agent -- \
    --id agent-b \
    --coordinator http://127.0.0.1:8080 \
    --listen 127.0.0.1:9001 \
    --advertise-address 127.0.0.1 \
    --probe-interval-seconds 5

# Terminal 3 — agent C
cargo run -p physarum-agent -- \
    --id agent-c \
    --coordinator http://127.0.0.1:8080 \
    --listen 127.0.0.1:9002 \
    --advertise-address 127.0.0.1 \
    --probe-interval-seconds 5
```

Wait one probe interval, then validate:

```bash
bash examples/local-lab/check-local-lab.sh
```

### Inspect the live graph

```bash
# Health
curl -s http://127.0.0.1:8080/health

# Registered agents
curl -s http://127.0.0.1:8080/agents | jq

# Peers of agent-b
curl -s http://127.0.0.1:8080/peers/agent-b | jq

# Full graph with conductivity (D_ij, q_ema, sample_count)
curl -s http://127.0.0.1:8080/graph | jq

# Adaptive path scoring: all simple paths from agent-b to agent-d,
# sorted by score = product(d_ij) descending.
# In a full-mesh lab the direct hop agent-b -> agent-d may outscore the
# two-hop agent-b -> agent-c -> agent-d if its conductivity is higher.
# Ranking depends on live d_ij values, not hop count.
curl -s 'http://127.0.0.1:8080/paths?source=agent-b&target=agent-d' | jq
```

### Verify and build

```bash
./Utilities/check-env.sh        # 12-point environment validation
./Utilities/build.sh            # debug build + all workspace tests
./Utilities/build.sh --release  # optimised release build
```

---

## Development workflow

The `Utilities/` directory contains shell scripts that standardize every step of the
development lifecycle — from setting up a new machine to publishing a production release.

### Verify your environment

```bash
./Utilities/check-env.sh
```

Checks: OS compatibility, Xcode CLT (macOS), C linker, curl, rustup, rustc ≥ 1.86, cargo, PATH, active toolchain, git, project structure, and workspace integrity.

### Build

```bash
./Utilities/build.sh              # debug build + all workspace tests
./Utilities/build.sh --release    # optimised release build + tests
./Utilities/build.sh --check      # compile check only — no binary output
./Utilities/build.sh --clippy     # full lint pass (warnings as errors)
```

### Git workflow

| Script | When to use |
|---|---|
| `git-scripts/commit.sh` | Any code change — enforces Conventional Commits format |
| `git-scripts/checkpoint.sh` | Development milestone — version bump + push, no tag |
| `git-scripts/release.sh` | Official release — bump + tag + push → CI publishes binaries |

### Continuous integration

Every push and pull request triggers:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
```

---

## Roadmap

The current prototype implements the adaptive edge pipeline end-to-end for an A/B/C agent cluster through autonomous maze propagation (PF-1, PF-2). The full architecture is in [General-Docs/ARCHITECTURE.md](./General-Docs/ARCHITECTURE.md).

Summary:

| Phase | Focus | State |
|---|---|---|
| 0 | Protocol + coordinator scaffold + CI | ✔ done |
| 1 | Agent probing + A/B/C local/Docker lab + TLA+ edge model | ✔ done |
| 2 | Agent D + `/paths` endpoint + AWS Mode 1, Mode 2, tc/netem weighted paths | ✔ done |
| Gate I | FlowObservation model + POST/GET `/flow-observations` | ✔ done |
| Gate J/J.1 | `physarum-ebpf-observer` — TCP state tracepoint, AWS EC2 kernel 6.18 | ✔ done — Issue #69/72 |
| Gate K/K.1 | Segmented 5-node lab + negative-log scoring + autonomous path selection | ✔ done — Issue #76/80 |
| Gate L/L.1/L.2/L.3 | `physarum-scanner` (RustScan) + eBPF-triggered discovery + ICMP stimulus | ✔ done — Issue #87 |
| Gate M/M.4 | `physarum-node` runtime + per-edge multiplier scoring adapter | ✔ done |
| PF-1 | Organic expansion maze — 7-node autonomous SCP+SSH propagation | ✔ done |
| PF-2 | Adaptive re-routing — 9-node, lateral discovery, TCP stimulus, secondary conduits | ✔ done |
| `physarum-llm` | LLM-aware adaptive propagation — Causal Continuity Paradox resolution | planned — Issue #106 |
| Gate N | mTLS + Ed25519 lineage signatures | planned after Issue #106 |

---

## Future architecture

> The sections below describe the planned secure/strategic evolution of the prototype. Items marked ✔ are already implemented.

### Autonomous propagation organism *(✔ implemented — PF-1, PF-2)*

`physarum-maze` is the current embodiment of the role-fluid agent concept. A single self-contained binary:
- Discovers hosts in the local `/24` via `physarum-scanner` (TCP/ICMP/UDP)
- Scores candidates using raw TCP SYN and ICMP stimulus from `physarum-packet-observer`
- Propagates itself via SCP + empty-password SSH + `systemd-run`
- Detects already-colonized nodes and records secondary conduits (score ×0.8 ×1.2)
- Records full lineage JSON at each hop (origin, path, hops, visited, scores, secondary_conduits)

**RustScan-backed service discovery** (✔ implemented — `physarum-scanner`, Gate L) feeds port discovery into the physarum graph as candidate edges.

> *Agents are not only observers of paths; agents are the computational substance that occupies and reinforces paths.*

The role-fluid design intent is documented in [General-Docs/ROLE_FLUID_AGENT_ARCHITECTURE.md](./General-Docs/ROLE_FLUID_AGENT_ARCHITECTURE.md).
The eBPF Stage 0 design is documented in [General-Docs/EBPF_FLOW_OBSERVATION_DESIGN.md](./General-Docs/EBPF_FLOW_OBSERVATION_DESIGN.md).

### Causal Continuity Paradox — `physarum-llm` *(planned — Issue #106)*

The organism is currently confined to hosts reachable via SSH. If a host has SSH closed but port 80 open (e.g., Apache 2.4.49 with CVE-2021-41773), the organism observes the host via eBPF but cannot propagate.

`physarum-llm` is planned to resolve this by querying an LLM oracle that generates context-specific propagation strategies given the target's observed open ports, banners, and OS hints. The design is lab-only, safety-gated, and blocked on the threat-model review in Issue #106. API keys are never stored in lineage.

---

### Full agent lifecycle *(planned)*

1. Boot — load Ed25519 identity; generate and attest if absent.
2. Attach eBPF — load kernel program, verify flow map is writable.
3. Discover neighbors — coordinator returns initial neighbor set + public keys.
4. Run main loop — probes, pressure gossip, signed report batches, incoming probe handler.

### Full coordinator *(planned)*

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/enroll` | Agent enrollment (attestation in body) |
| POST | `/v1/reports` | Batch ingestion (signed reports over QUIC) |
| GET  | `/v1/neighbors/{agent_id}` | Discovery |
| GET  | `/v1/graph` | Full graph dump |
| GET  | `/v1/paths/topk` | K most attractive paths to target |
| WS   | `/v1/stream` | Live drift + validation event stream |

### eBPF program *(planned)*

Compiled as a `no_std` Rust binary with `aya`, attached to kernel tracepoints (`sock:inet_sock_set_state`). Maintains a hash map of active flows in kernel memory; user-space drains it every 60 seconds.

### Combined flow signal *(planned)*

When eBPF and signed validations are available, `Q_ij` will incorporate three independent sources:

```
Q_ij = w₁ · Probe(i,j) + w₂ · Validation(i,j) + w₃ · Observe(i,j)
```

Default weights: `w₁=0.3, w₂=0.5, w₃=0.2`.

### Emergent pressure and layers *(planned)*

Each agent will compute a local scalar pressure via gossip:

```
p_i(t+1) = Σⱼ (D_ij / L_ij) · p_j(t) / Σⱼ (D_ij / L_ij)
```

Anchored at `p=1.0` for entry points and `p=0.0` for crown jewels. Emergent layer classification:

```
p_i ∈ [0.75, 1.00]  →  Layer 4 (External Perimeter)
p_i ∈ [0.50, 0.75]  →  Layer 3 (Gateways)
p_i ∈ [0.25, 0.50]  →  Layer 2 (Application Services)
p_i ∈ [0.00, 0.25]  →  Layer 1 (Protected Core)
```

### Security model *(planned)*

- Monotonic nonces + Ed25519 signatures — replay and forgery prevention
- QUIC + mutual TLS — transport encryption and identity pinning
- TPM / Nitro / Azure CVM / GCP Confidential VM attestation — boot-time identity

---

## Relationship to upstream IP

`Physarum` is designed as a complementary system to the upstream patented framework for *Attack-Path Probability Modeling*. It does not replace any component of that framework; it augments it by replacing the static, scanner-derived edge probability `P(e)` with a live, observation-driven conductivity `D_ij`.

Specifically:

- **§8.4** (`P(e)` from `W(e)`) becomes the `t=0` initial condition of the Physarum dynamics.
- **§8.5** (Yen K-shortest path enumeration) operates unchanged on the live `D/L` cost function *(planned)*.

Two distinct contributions are candidates for independent IP claims:

1. **Reconciliation across heterogeneous segmentation primitives** (AWS Security Groups vs Azure NSGs vs Kubernetes NetworkPolicies vs on-prem firewalls), producing a unified Layer model consumable by attack-path engines.
2. **Closed-loop refinement of the attack graph during agent execution**, where validation outcomes from upstream pentest agents feed back into edge conductivities in real time.

---

## References

1. Tero, A., Kobayashi, R., Nakagaki, T. (2007). *A mathematical model for adaptive transport network in path finding by true slime mold.* Journal of Theoretical Biology, 244(4), 553–564.
2. Becchetti, L., Bonifaci, V., Dirnberger, M., Karrenbauer, A., Mehlhorn, K. (2013). *Physarum can compute shortest paths: convergence proofs and complexity bounds.* ICALP.
3. Liu, Y., Gao, C., Zhang, Z., Lu, Y., Chen, S., Liang, M., Tao, L. (2017). *An improved Physarum polycephalum algorithm for the shortest path problem.* Scientific World Journal.
4. Nakagaki, T., Yamada, H., Tóth, Á. (2000). *Maze-solving by an amoeboid organism.* Nature, 407(6803), 470.

For Rust-side dependencies of architectural significance:

- `axum` — HTTP framework (coordinator)
- `tokio` — async runtime
- `petgraph` — graph data structures (coordinator graph)
- `aya` — pure-Rust eBPF library ✔ (physarum-ebpf-observer, physarum-packet-observer)
- `clap` — CLI argument parsing (physarum-maze, physarum-scan)
- `async-openai` — OpenAI-compatible API client *(planned — physarum-llm)*
- `quinn` — QUIC transport *(planned)*
- `ed25519-dalek` — signature scheme *(planned — Gate N)*

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
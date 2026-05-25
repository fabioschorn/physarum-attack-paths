# physarum-attack-paths

> **Bio-inspired attack-path organism for adaptive security graph discovery.** `physarum-attack-paths` is a Rust research prototype that turns distributed network evidence into a living attack-path graph. It combines adaptive edge scoring (`Q_ij → q_ema → D_ij`), active probing, eBPF/packet-level stimulus observation, native discovery through `physarum-scanner`, and controlled lab propagation. PF-1 and PF-2 validated the current organism model in real AWS VPC labs: one seed expanded through an unknown maze, re-sensed new structure, recognized an already-colonized node, and preserved a secondary conduit.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-research--prototype-orange.svg)](https://github.com/fabioschorn/physarum-attack-paths)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/fabioschorn/physarum-attack-paths/releases)
[![CI](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml/badge.svg)](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml)

`physarum-attack-paths` is a distributed system for discovering, validating, and continuously refining cybersecurity attack paths across heterogeneous environments. It replaces a static, scanner-centric view of the network with a **living topology**: local observations and validation outcomes reinforce useful paths while unused or blocked paths decay.

The project is inspired by *Physarum polycephalum*, a slime mold that forms efficient transport networks without central control. In this project, the network graph is **observed**, not declared. Layer assignment, path preference, and drift emerge from behavior.

---

## Safety and scope

This repository is a **controlled research prototype**. The propagation labs are designed for owned, isolated, authorized environments only.

```text
Allowed scope: local labs, Docker labs, and owned AWS lab VPCs.
Not allowed: public targets, Internet scanning, production deployment, or unbounded propagation.
```

PF-1/PF-2 use intentionally weak lab conditions, including empty-password SSH, to validate organism behavior in a closed environment. That is not a production deployment pattern. Secure identity, mTLS, signed lineage, and stronger trust controls are planned for Gate N after Issue #106.

---

## Current status

**Research prototype** — the adaptive graph, sensing, discovery, and PF organism labs are implemented and validated.

| Area | State |
|---|---|
| Shared protocol types (`physarum-protocol`) | ✔ implemented |
| Coordinator and peer-probing agent (`physarum-server`, `physarum-agent`) | ✔ implemented |
| Flow and packet observation (`physarum-ebpf-observer`, `physarum-packet-observer`) | ✔ implemented — AWS EC2 validated, kernel 6.18 |
| Native discovery engine (`physarum-scanner`) | ✔ implemented — Gate L |
| Probe execution library (`physarum-probe`) | ✔ implemented |
| Role-fluid runtime (`physarum-node`, `physarum-node-runtime`) | ✔ implemented — Gate M/M.4 |
| Self-propagating maze organism (`physarum-maze`) | ✔ implemented — PF-1/PF-2 |
| Flow observations API (`POST/GET /flow-observations`) | ✔ implemented — Gate I |
| Adaptive path scoring (`GET /paths`) | ✔ implemented — Gate K.1 |
| TLA+ formal models (`formal/tla`) | ✔ implemented — single-edge, multi-agent, negative-log |
| Local and Docker labs | ✔ implemented |
| AWS Mode 1 / Mode 2 / Gate K/K.1 labs | ✔ validated |
| AWS PF-1 organic expansion maze | ✔ validated — 7-node autonomous propagation lab |
| AWS PF-2 adaptive re-routing | ✔ validated — 9-node lateral discovery + TCP stimulus + secondary conduit lab |
| `physarum-llm` | planned — Issue #106 |
| Gate N secure organism identity | planned after Issue #106 |

See [General-Docs/ARCHITECTURE.md](./General-Docs/ARCHITECTURE.md) for the canonical architecture and [General-Docs/QUALITY_GATE.md](./General-Docs/QUALITY_GATE.md) for gate definitions and acceptance criteria. Longer-term research ideas live in [General-Docs/INSIGHTS_AND_BRAINSTORM.md](./General-Docs/INSIGHTS_AND_BRAINSTORM.md).

---

## Table of contents

- [Safety and scope](#safety-and-scope)
- [Current status](#current-status)
- [Motivation](#motivation)
- [Conceptual model](#conceptual-model)
- [Architecture](#architecture)
- [Mathematical core](#mathematical-core)
- [Repository layout](#repository-layout)
- [Labs](#labs)
- [Quick start](#quick-start)
- [Development workflow](#development-workflow)
- [Roadmap](#roadmap)
- [Planned evolution](#planned-evolution)
- [Relationship to upstream IP](#relationship-to-upstream-ip)
- [References](#references)

---

## Motivation

Traditional attack-path analysis often fails in three ways.

The **single-vantage-point problem**: scanners see what they can reach from one location, not necessarily what exists across NAT, cloud segmentation, Kubernetes policies, on-prem firewalls, and zero-trust boundaries.

The **declarative-topology problem**: assets may claim to belong to a layer or zone, but real reachability can drift because of security group changes, permissive firewall rules, forgotten routes, or broken network policies.

The **stale-snapshot problem**: many attack graphs are computed once from scanner output and then treated as truth, even though the environment changes before validation or remediation happens.

`Physarum` addresses these problems by treating attack-path topology as an emergent property of distributed agent activity. There is no single declared layer map and no permanently frozen `P(e)`. There is a reinforcement-decay process across observed edges, and the graph that survives is the graph supported by evidence.

---

## Conceptual model

The biological *Physarum polycephalum* forms efficient transport networks by reinforcing tubes that carry flow and weakening tubes that do not. This project maps that idea onto security-path discovery.

| Biological concept | Security interpretation |
|---|---|
| Inoculation point | Externally reachable asset or known starting host |
| Food source | Crown jewel, high-criticality asset, or protected core |
| Tube between nodes | Candidate attack edge between hosts or agents |
| Tube thickness `D_ij` | Edge conductivity; dynamic replacement for static edge probability |
| Cytoplasm flow `Q_ij` | Evidence from probes, observations, and validation outcomes |
| Reinforcement | Successful, stable, low-cost reachability |
| Decay | Lack of evidence, blocked reachability, or weak path quality |

The system does **not** simulate slime mold. It borrows the mathematical shape of reinforcement and decay because that shape is useful for adaptive path-finding.

---

## Architecture

### Current prototype

The implemented prototype has three cooperating layers.

```text
1. Adaptive graph layer
   physarum-server + physarum-agent
   -> registration, peer probing, ProbeReport ingest, /graph, /paths

2. Sensing and discovery layer
   physarum-ebpf-observer
   physarum-packet-observer
   physarum-scanner
   physarum-probe
   -> TCP/ICMP stimulus capture, physarum-scanner discovery, probe execution

3. Organism runtime layer
   physarum-node
   physarum-node-runtime
   physarum-maze
   -> runtime consolidation, autonomous maze propagation, lineage memory
```

At the graph layer, agents produce evidence and the coordinator turns that evidence into adaptive edge conductivity:

```text
agents register -> agents probe -> reports arrive -> Q_ij -> q_ema -> D_ij -> /paths
```

At the sensing layer, nodes can discover candidate corridors instead of relying only on a predeclared peer list:

```text
TCP/ICMP stimulus -> candidate host -> scanner/probe -> edge evidence
```

At the organism layer, `physarum-maze` validated the current pre-final behavior in AWS:

```text
PF-1: one seed expands through a 7-node maze and records lineage.
PF-2: the organism re-senses new structure, handles TCP stimulus, avoids duplicate propagation into an already-colonized node, and records a secondary conduit.
```

The current architecture is therefore no longer only a fixed server/client prototype. It is a research organism composed of graph memory, local senses, bounded discovery, propagation, and lineage.

### Current limitations

The current organism is intentionally constrained:

```text
propagation is lab-only
SSH-based propagation is the only validated propagation path
lineage is structured but not yet cryptographically signed
node identity is not yet mTLS-backed
LLM-assisted propagation is not implemented
```

These limitations are deliberate and tracked in the roadmap.

---

## Mathematical core

The adaptive edge pipeline is implemented in `physarum-agent` and `physarum-server` and is used as the foundation for path scoring.

### Stimulus signal (`Q_ij`)

Each probe report contains `success_rate ∈ [0, 1]` and `avg_rtt_ms`.

```text
latency_score = 1 / (1 + avg_rtt_ms / 100)

Q_ij = 0                                                      if success_rate = 0
Q_ij = clamp(0.7 · success_rate + 0.3 · latency_score, 0, 1)   otherwise
```

### EMA-smoothed signal (`q_ema`)

```text
q_ema(t+1) = 0.3 · Q_ij + 0.7 · q_ema(t)
```

`α = 0.3` gives quick response to improvement while smoothing short-term noise.

### Sigmoid growth drive (`f`)

```text
f(x) = x² / (1 + x²)
```

This saturates growth and prevents runaway reinforcement.

### Edge conductivity (`D_ij`)

```text
D_ij(t+1) = clamp(D_ij(t) + f(q_ema) · (1 - D_ij) - 0.1 · D_ij, 0, 1)
```

Where:

```text
f(q_ema) · (1 - D_ij)  -> growth term
0.1 · D_ij             -> decay term
```

Under sustained successful probes:

```text
D* = f(1) / (f(1) + 0.1) = 0.5 / 0.6 ≈ 0.833
```

The TLA+ models in `formal/tla/` verify that `q_ema` and `D_ij` remain in `[0, 1]` and that the negative-log path model preserves expected scoring properties.

---

## Repository layout

This is a high-level map of the repository. It is intentionally not exhaustive; the GitHub tree is the source of truth for exact files.

```text
crates/
  Rust workspace crates for protocol types, coordinator APIs, agents, observers,
  scanners, probe execution, node runtime, and the maze organism.

examples/
  Local, Docker, and AWS validation labs, including the PF-1/PF-2 organism labs.

formal/
  TLA+ models for adaptive edge scoring and path-safety properties.

General-Docs/
  Canonical architecture, quality gates, design notes, and research/backlog ideas.

Utilities/
  Developer build, validation, distribution, and release helper scripts.

.github/
  CI and release automation.
```

---

## Labs

| Lab | What it validates | Status |
|---|---|---|
| `examples/local-lab` | A/B/C coordinator and agents on localhost | ✔ implemented |
| `examples/docker-lab` | A/B/C/D agent graph in Docker Compose | ✔ implemented |
| `examples/aws-lab/terraform` | EC2/VPC Mode 1, Mode 2, tc/netem, Gate K/K.1 | ✔ validated |
| `examples/aws-lab/terraform-pf1` | 7-node autonomous expansion maze | ✔ validated |
| `examples/aws-lab/terraform-pf2` | 9-node adaptive re-routing with TCP stimulus and secondary conduits | ✔ validated |
| `formal/tla` | Formal models checked with TLC | ✔ implemented |

---

## Quick start

> This is a research prototype. Do not deploy on production hosts without security review.

### Prerequisites

- Rust 1.86 or later
- Docker Desktop ≥ 4.25 or Docker Engine ≥ 24 with Compose v2
- `curl` and `jq`
- macOS or Linux on x86_64 / ARM64

### Docker lab

```bash
cd examples/docker-lab
docker compose up --build
```

Wait for the agents to register, then validate:

```bash
bash check-docker-lab.sh
```

Stop and clean up:

```bash
docker compose down
```

### Local lab

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

Inspect the graph:

```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/agents | jq
curl -s http://127.0.0.1:8080/graph | jq
curl -s 'http://127.0.0.1:8080/paths?source=agent-b&target=agent-d' | jq
```

### Verify and build

```bash
./Utilities/check-env.sh
./Utilities/build.sh
./Utilities/build.sh --release
```

---

## Development workflow

The `Utilities/` directory standardizes environment checks, builds, tests, and releases.

```bash
./Utilities/check-env.sh
./Utilities/build.sh
./Utilities/build.sh --check
./Utilities/build.sh --clippy
```

Every pull request runs:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
```

Git helper scripts live under `git-scripts/`:

| Script | Purpose |
|---|---|
| `git-scripts/commit.sh` | Conventional Commit helper |
| `git-scripts/checkpoint.sh` | Development checkpoint without tag |
| `git-scripts/release.sh` | Version bump, tag, push, and release pipeline |

---

## Roadmap

The current prototype has completed the component gates through Gate M and the pre-final organism labs PF-1/PF-2.

| Phase | Focus | State |
|---|---|---|
| 0 | Protocol + coordinator scaffold + CI | ✔ done |
| 1 | Agent probing + A/B/C local/Docker lab + TLA+ edge model | ✔ done |
| 2 | Agent D + `/paths` endpoint + AWS Mode 1/2 validation | ✔ done |
| Gate I | FlowObservation model and API | ✔ done |
| Gate J/J.1 | eBPF TCP state observation on AWS EC2 | ✔ done |
| Gate K/K.1 | Segmented adaptive path selection and negative-log scoring | ✔ done |
| Gate L/L.1/L.2/L.3 | `physarum-scanner` discovery and TCP/ICMP stimulus sensing | ✔ done |
| Gate M/M.4 | `physarum-node` runtime convergence and probe consolidation | ✔ done |
| PF-1 | Organic expansion maze | ✔ done |
| PF-2 | Adaptive re-routing and secondary conduits | ✔ done |
| Issue #106 | LLM-aware propagation design for the Causal Continuity Paradox | planned |
| Gate N.0 / Issue #89 | Secure organism identity, mTLS, and lineage threat model | planned after #106 |

---

## Planned evolution

### Issue #106 — Causal Continuity Paradox

The organism is currently confined to hosts reachable through the validated SSH/SCP lab propagation path. If a host is reachable only through a non-SSH service, the organism may observe the host but cannot yet cross it.

Issue #106 explores whether a lab-only, safety-gated `physarum-llm` component can select context-specific propagation strategies from observed ports, banners, and OS hints. This is not implemented and remains pending design and safety review.

### Gate N — secure organism identity

After Issue #106 clarifies the future propagation surface, Gate N will define and implement the secure identity model:

```text
mTLS node identity
signed lineage / hop records
anti-replay controls
capability-aware authorization
clear lab mode vs secure mode separation
```

No production security guarantees are claimed before Gate N.

---

## Relationship to upstream IP

`Physarum` is designed as a complementary system to the upstream patented framework for *Attack-Path Probability Modeling*. It does not replace that framework; it augments it by replacing static, scanner-derived edge probability `P(e)` with live, observation-driven conductivity `D_ij`.

Specifically:

- **§8.4** (`P(e)` from `W(e)`) becomes the `t=0` initial condition of the Physarum dynamics.
- **§8.5** (Yen K-shortest path enumeration) can operate on the live `D/L` cost function.

Potential independent contribution areas:

1. **Reconciliation across heterogeneous segmentation primitives** such as AWS Security Groups, Azure NSGs, Kubernetes NetworkPolicies, and on-prem firewalls.
2. **Closed-loop refinement of the attack graph during agent execution**, where validation outcomes feed back into edge conductivities in real time.

---

## References

1. Tero, A., Kobayashi, R., Nakagaki, T. (2007). *A mathematical model for adaptive transport network in path finding by true slime mold.* Journal of Theoretical Biology, 244(4), 553–564.
2. Becchetti, L., Bonifaci, V., Dirnberger, M., Karrenbauer, A., Mehlhorn, K. (2013). *Physarum can compute shortest paths: convergence proofs and complexity bounds.* ICALP.
3. Liu, Y., Gao, C., Zhang, Z., Lu, Y., Chen, S., Liang, M., Tao, L. (2017). *An improved Physarum polycephalum algorithm for the shortest path problem.* Scientific World Journal.
4. Nakagaki, T., Yamada, H., Tóth, Á. (2000). *Maze-solving by an amoeboid organism.* Nature, 407(6803), 470.

For Rust-side dependencies of architectural significance:

- `axum` — HTTP framework for the coordinator
- `tokio` — async runtime
- `petgraph` — graph data structures
- `aya` — pure-Rust eBPF library
- `clap` — CLI argument parsing
- `async-openai` — OpenAI-compatible API client *(planned — physarum-llm)*
- `quinn` — QUIC transport *(planned)*
- `ed25519-dalek` — signature scheme *(planned — Gate N)*

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for full terms.

---

## Contributing

Contributions require signing the Contributor License Agreement (CLA). The CLA bot will guide you through the process on your first pull request.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development workflow, code style, and test requirements. Security issues should be reported according to [SECURITY.md](./SECURITY.md).

---

*"The slime mold has no brain, no nervous system, no central authority. It solves the maze anyway."*

# physarum-attack-paths

> **Bio-inspired attack-path organism for controlled security research.** `physarum-attack-paths` is a Rust research prototype that turns local network observations, adaptive sensing, pattern evidence, LLM reasoning, policy decisions, and lineage memory into a living attack-path discovery organism.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-research--prototype-orange.svg)](https://github.com/fabioschorn/physarum-attack-paths)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/fabioschorn/physarum-attack-paths/releases)
[![CI](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml/badge.svg)](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml)

`physarum-attack-paths` studies how a distributed organism can discover and prioritize viable security paths in changing environments. Instead of treating a scan as a static snapshot, the system collects evidence from ports, banners, HTTP patterns, packet/eBPF stimuli, runtime observations, LLM recommendations, policy-gate decisions, and lineage history.

The project is inspired by *Physarum polycephalum*, a slime mold that reinforces useful paths and abandons weak ones. This repository does **not** simulate slime mold biology. It borrows the reinforcement/decay intuition and applies it to controlled attack-path research.

---

## Safety and scope

This repository is a **controlled research prototype**. It is intended for owned, isolated, authorized labs only.

```text
Allowed scope:
  - local labs
  - Docker labs
  - owned AWS lab VPCs
  - controlled research environments

Not allowed:
  - public targets
  - Internet scanning
  - production deployment
  - unbounded propagation
  - unauthorized exploitation
```

LLM-assisted behavior is **lab-only**, policy-gated, and disabled unless explicitly configured. CVE-aware reasoning is treated as evidence and proposal generation, not automatic exploitation. `PolicyGate` remains the local decision boundary.

Secure identity, mTLS, signed lineage, and stronger trust controls are planned for Gate N. No production security guarantees are claimed before that gate.

---

## Current status

The current project focus is the `physarum-maze` organism path: adaptive sensing, structured evidence, real LLM Docker validation, and lineage-recorded policy decisions.

| Area | State |
|---|---|
| Rust workspace / protocol foundations | ✔ implemented |
| Adaptive graph scoring (`Q_ij`, `q_ema`, `D_ij`, `/paths`) | ✔ implemented and validated in earlier gates |
| Packet and flow observation (`physarum-ebpf`, packet observers) | ✔ implemented for lab research |
| Native scanner (`physarum-scan` / `physarum-scanner`) | ✔ implemented |
| Structured sensing (`SensingProfile`, `SensingResult`, `PortScan`) | ✔ implemented |
| Adaptive service classification (`ConfirmedWeb`, `LikelyWeb`, `UnknownNeedsMoreSensing`, `ConfirmedNonWeb`) | ✔ implemented |
| Nuclei-inspired native evidence engine (`physarum-spore` / `physarum-sporangium`) | ✔ implemented as native Rust pattern evidence layer |
| Maze organism (`physarum-maze`) | ✔ primary active binary |
| LLM contracts and OpenAI-compatible client (`physarum-llm`) | ✔ implemented and Docker-validated |
| Real LLM Docker Lab | ✔ PF-4 validated |
| Adaptive startup/runtime sensing profiles | ✔ PF-5 / Issue #126 validated after PR #127 merge |
| CVE-aware spore enrichment and LLM exploit-path proposal evidence | next — Issue #128 |
| AWS Lab with real LLM | planned after Docker evidence gates |
| Gate N secure identity / mTLS / signed lineage | planned after LLM/evidence loop stabilizes |

The current release line uses these primary binaries:

```text
physarum-maze       # organism runtime / evidence loop / lineage
physarum-scan       # native scanner binary
physarum-spore      # native Nuclei-inspired evidence-pattern binary
physarum-sporangium # pattern runner / evidence engine crate
```

Older coordinator-oriented crates still exist for graph research and historical gates, but the active organism work now centers on `physarum-maze` and its embedded sensing/evidence/LLM loop.

---

## Table of contents

- [Safety and scope](#safety-and-scope)
- [Current status](#current-status)
- [Conceptual model](#conceptual-model)
- [Architecture](#architecture)
- [Evidence pipeline](#evidence-pipeline)
- [LLM and PolicyGate](#llm-and-policygate)
- [Mathematical core](#mathematical-core)
- [Repository layout](#repository-layout)
- [Labs](#labs)
- [Quick start](#quick-start)
- [Development workflow](#development-workflow)
- [Roadmap](#roadmap)
- [References](#references)

---

## Conceptual model

The organism follows two principles.

First, the network is **observed**, not assumed. A host becomes interesting because the agent sees evidence: an open port, a banner, a service fingerprint, an ICMP/TCP/eBPF stimulus, a pattern finding, or a prior lineage result.

Second, the agent separates **evidence**, **proposal**, and **decision**.

```text
Evidence:
  SensingResult, PortScan, PatternFindingSummary, VulnerabilityCandidate

Proposal:
  LLM-generated PropagationStrategy or exploit-path proposal

Decision:
  PolicyGate accepted/rejected result

Memory:
  LlmAttemptEvidence and lineage
```

This keeps the LLM useful for reasoning without making it the authority. The LLM proposes. `PolicyGate` decides. Lineage remembers.

---

## Architecture

### Current organism path

```text
┌──────────────────────────────────────────────────────────────┐
│                         physarum-maze                        │
│                                                              │
│  startup_sensing / ICMP / TCP-eBPF stimulus                  │
│        │                                                     │
│        ▼                                                     │
│  embedded physarum-scan / physarum-scanner                   │
│        │                                                     │
│        ▼                                                     │
│  SensingResult / PortScan                                    │
│        │                                                     │
│        ▼                                                     │
│  physarum-spore / physarum-sporangium                        │
│        │                                                     │
│        ▼                                                     │
│  PatternFindingSummary / vulnerability_candidates            │
│        │                                                     │
│        ▼                                                     │
│  DiscoveryQuery                                              │
│        │                                                     │
│        ▼                                                     │
│  physarum-llm                                                │
│        │                                                     │
│        ▼                                                     │
│  PropagationStrategy / exploit-path proposal                 │
│        │                                                     │
│        ▼                                                     │
│  PolicyGate                                                  │
│        │                                                     │
│        ▼                                                     │
│  LlmAttemptEvidence / lineage                                │
└──────────────────────────────────────────────────────────────┘
```

### Component roles

| Component | Role |
|---|---|
| `physarum-maze` | Main organism runtime, seed/propagated behavior, evidence loop, policy-gated propagation, lineage |
| `physarum-scan` / `physarum-scanner` | Native scanning and structured sensing profiles |
| `physarum-spore` / `physarum-sporangium` | Native evidence-pattern engine inspired by Nuclei concepts |
| `physarum-llm` | Provider-neutral contracts, OpenAI-compatible client, mock client, `DiscoveryQuery`, `PropagationStrategy`, evidence records |
| `physarum-ebpf` / observers | Runtime packet/flow stimuli for controlled labs |
| `physarum-probe` | Probe execution primitives used by earlier graph layers |
| `physarum-agent` / `physarum-server` | Earlier adaptive graph/coordinator research components |
| `formal/tla` | Formal models for scoring and path-safety properties |

### Adaptive sensing profiles

PF-5 introduced trigger-aware sensing profiles:

| Trigger | Profile | Semantic equivalent |
|---|---|---|
| Startup seed behavior | `StartupLocalDiscovery` | local `/24`, SYN-style discovery semantics, focused service port list |
| ICMP stimulus | `RuntimeIcmpFast` | fast common-port profile, conceptual `-T4 -F` |
| TCP/eBPF stimulus | `RuntimeTcpEbpfFast` | fast common-port no-discovery profile, conceptual `-T4 -F -Pn` |
| Service/version enrichment | `ServiceVersion` | conceptual `-sV`, currently a hook/stub for deeper enrichment |

The startup path is important: the Docker lab should not require an external ping harness for the organism to begin sensing. Runtime stimulus paths remain validated separately.

---

## Evidence pipeline

The evidence pipeline is intentionally layered.

```text
1. Startup or runtime stimulus
2. Adaptive scanner profile
3. Open ports, banners, service guesses, version hints
4. HTTP/TLS/web-like classification and targeted re-sensing
5. physarum-spore pattern evidence
6. Optional CVE/vulnerability candidate enrichment
7. DiscoveryQuery to LLM
8. LLM proposal
9. PolicyGate decision
10. Lineage record
```

### CVE-aware enrichment

Issue #128 tracks the next step: CVE-aware spore enrichment and LLM exploit-path proposal evidence.

The expected model is:

```text
service/version/banner evidence
  -> physarum-spore CVE enrichment
  -> vulnerability_candidates in DiscoveryQuery
  -> LLM identifies likely CVE/path
  -> LLM proposes exploit-path strategy
  -> agent logs proposal in LlmAttemptEvidence / lineage
  -> PolicyGate remains final decision boundary
```

For this milestone, exploit execution does **not** need to be validated. The Docker Lab must prove that the LLM receives CVE-enriched evidence and returns a structured proposal that is recorded by the agent.

---

## LLM and PolicyGate

`physarum-llm` supports mock and OpenAI-compatible client paths. The Docker Lab can run with mock behavior or a real LLM endpoint.

Environment variables used by the Docker Lab include:

```env
PHYSARUM_LLM_ENDPOINT=https://api.openai.com
PHYSARUM_LLM_MODEL=gpt-4o-mini
LLM_API_KEY=...
PHYSARUM_LLM_LOG_PROMPTS=false
PHYSARUM_ENABLE_DOCKER_ICMP_HARNESS=false
```

Sensitive local files should live under `examples/*/sensitive-info/` and must not be committed. The repository should only commit placeholders such as `.env.example` and README files.

LLM logging is guarded:

```text
PHYSARUM_LLM_LOG_PROMPTS=false/default:
  log metadata only

PHYSARUM_LLM_LOG_PROMPTS=true/lab-only:
  allow full prompt/raw response logs for validation evidence
```

Policy rule:

```text
LLM proposes.
PolicyGate decides.
Lineage records.
```

---

## Mathematical core

The adaptive graph layer uses a Physarum-inspired reinforcement/decay model. It remains relevant for path scoring and future graph memory even while the active organism work focuses on `physarum-maze`.

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

### Edge conductivity (`D_ij`)

```text
f(x) = x² / (1 + x²)

D_ij(t+1) = clamp(D_ij(t) + f(q_ema) · (1 - D_ij) - 0.1 · D_ij, 0, 1)
```

Under sustained successful probes:

```text
D* = f(1) / (f(1) + 0.1) = 0.5 / 0.6 ≈ 0.833
```

The TLA+ models in `formal/tla/` verify that the scoring variables remain bounded and that the negative-log path model preserves expected scoring properties.

---

## Repository layout

```text
crates/
  Rust workspace crates for protocol types, agents, scanners, observers,
  pattern evidence, LLM contracts, node runtime, and the maze organism.

examples/
  Local, Docker, and AWS validation labs. Sensitive local lab files should use
  sensitive-info/ directories with committed examples only.

formal/
  TLA+ models for adaptive edge scoring and path-safety properties.

General-Docs/
  Architecture, quality gates, design notes, and research/backlog ideas.

Utilities/
  Developer build, validation, Docker Lab, release, and helper scripts.

.github/
  CI and release automation.
```

Local upstream source clones used for analysis, such as `nuclei/`, are ignored by `.gitignore` and must not be committed. Native behavior should be ported into Rust workspace crates instead of vendoring external projects.

---

## Labs

| Lab | What it validates | Status |
|---|---|---|
| `examples/local-lab` | Earlier coordinator/agent graph behavior | ✔ implemented |
| `examples/docker-lab` | Earlier A/B/C/D graph lab in Docker Compose | ✔ implemented |
| `docker/docker-compose-lab.yml` + `Utilities/docker-lab.sh` | `physarum-maze`, adaptive sensing, mock/real LLM, lineage evidence | ✔ PF-4/PF-5 validated |
| `examples/pf-4-real-llm-lab` | Local sensitive-info process and real LLM configuration | ✔ implemented |
| `examples/aws-lab/terraform` | EC2/VPC Mode 1, Mode 2, tc/netem, Gate K/K.1 | ✔ validated |
| `examples/aws-lab/terraform-pf1` | 7-node autonomous expansion maze | ✔ validated |
| `examples/aws-lab/terraform-pf2` | 9-node adaptive re-routing with TCP stimulus and secondary conduits | ✔ validated |
| Future Docker CVE Lab | CVE-aware spore enrichment and LLM proposal evidence | next — Issue #128 |
| Future AWS LLM Lab | Real LLM reasoning in owned AWS lab | planned after Docker evidence gates |
| `formal/tla` | Formal models checked with TLC | ✔ implemented |

---

## Quick start

> This is a research prototype. Do not deploy on production hosts without security review.

### Prerequisites

- Rust 1.86 or later; the repository pins Rust 1.86.0 through `rust-toolchain.toml`
- Docker Desktop ≥ 4.25 or Docker Engine ≥ 24 with Compose v2
- `curl` and `jq`
- Linux or macOS development host

### Build and test

```bash
./Utilities/check-env.sh
./Utilities/build.sh
./Utilities/build.sh --release
cargo test --workspace
```

### Docker Maze Lab: default organic startup sensing

```bash
./Utilities/docker-lab.sh --clean
./Utilities/docker-lab.sh
```

Default behavior:

```text
PHYSARUM_ENABLE_DOCKER_ICMP_HARNESS=false
```

The seed agent should run startup sensing organically, discover Docker lab targets, build `DiscoveryQuery`, call the configured mock/real LLM path, pass through `PolicyGate`, and record `LlmAttemptEvidence` in lineage.

### Docker Maze Lab: runtime ICMP stimulus path

```bash
PHYSARUM_ENABLE_DOCKER_ICMP_HARNESS=true ./Utilities/docker-lab.sh
```

This explicitly validates the runtime ICMP stimulus path. It should not be required for startup sensing.

### Docker Maze Lab with real LLM

Create a local env file from the committed example, then run the lab:

```bash
cd examples/pf-4-real-llm-lab/sensitive-info
cp .env.example .env.local
# edit .env.local with your local provider key
source .env.local
cd ../../../..
./Utilities/docker-lab.sh
```

Expected env example:

```env
PHYSARUM_LLM_ENDPOINT=https://api.openai.com
PHYSARUM_LLM_MODEL=gpt-4o-mini
LLM_API_KEY=replace_me
PHYSARUM_LLM_LOG_PROMPTS=false
```

Never commit `.env.local` or any real API key.

### Classic graph Docker lab

```bash
cd examples/docker-lab
docker compose up --build
bash check-docker-lab.sh
docker compose down
```

### Local graph lab

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

---

## Development workflow

The `Utilities/` directory standardizes environment checks, builds, tests, Docker Lab execution, and releases.

```bash
./Utilities/check-env.sh
./Utilities/build.sh
./Utilities/build.sh --check
./Utilities/build.sh --clippy
```

Every pull request should satisfy:

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

| Phase / issue | Focus | State |
|---|---|---|
| Phase 0–2 | Protocol, coordinator, agents, local/Docker graph labs | ✔ done |
| Gate I–K | Flow observations, eBPF observation, adaptive path scoring | ✔ done |
| Gate L | Native scanner and TCP/ICMP stimulus sensing | ✔ done |
| Gate M | Runtime convergence and node consolidation | ✔ done |
| PF-1 | AWS organic expansion maze | ✔ done |
| PF-2 | AWS adaptive re-routing and secondary conduits | ✔ done |
| Issue #106 | DiscoveryQuery evidence loop and LLM-aware reasoning | ✔ implemented through PF-4/PF-5 work |
| Issue #114 | Structured scanner sensing layer | ✔ done |
| Issue #115 | Native Nuclei-inspired evidence engine | ✔ implemented as `physarum-spore` / `physarum-sporangium` |
| Issue #126 | Adaptive sensing profiles for startup, ICMP, TCP/eBPF | ✔ ready/complete after PR #127 merge |
| Issue #128 | CVE-aware spore enrichment and LLM exploit-path proposal evidence | next |
| AWS LLM Lab | Real LLM in owned AWS lab | planned after Docker #128 proof |
| Gate N | Secure organism identity, mTLS, signed lineage | planned |

---

## Planned evolution

### Issue #128 — CVE-aware evidence and LLM proposal

The next Docker proof should demonstrate:

```text
service/version/banner evidence
  -> vulnerability_candidates
  -> DiscoveryQuery
  -> LLM identifies likely CVE/path
  -> LLM returns exploit-path proposal
  -> PolicyGate evaluates
  -> lineage records
```

This is a reasoning/evidence milestone. It does not require exploit execution.

### Gate N — secure organism identity

After the LLM/evidence loop stabilizes, Gate N will define and implement:

```text
mTLS node identity
signed lineage / hop records
anti-replay controls
capability-aware authorization
clear lab mode vs secure mode separation
```

---

## References

1. Tero, A., Kobayashi, R., Nakagaki, T. (2007). *A mathematical model for adaptive transport network in path finding by true slime mold.* Journal of Theoretical Biology, 244(4), 553–564.
2. Becchetti, L., Bonifaci, V., Dirnberger, M., Karrenbauer, A., Mehlhorn, K. (2013). *Physarum can compute shortest paths: convergence proofs and complexity bounds.* ICALP.
3. Liu, Y., Gao, C., Zhang, Z., Lu, Y., Chen, S., Liang, M., Tao, L. (2017). *An improved Physarum polycephalum algorithm for the shortest path problem.* Scientific World Journal.
4. Nakagaki, T., Yamada, H., Tóth, Á. (2000). *Maze-solving by an amoeboid organism.* Nature, 407(6803), 470.

For Rust-side dependencies of architectural significance:

- `axum` — HTTP framework for earlier coordinator/API components
- `tokio` — async runtime
- `petgraph` — graph data structures
- `aya` — pure-Rust eBPF library
- `clap` — CLI argument parsing
- `reqwest` — HTTP client used by OpenAI-compatible client paths
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

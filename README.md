# physarum-attack-paths

[![License: PolyForm NC 1.0.0](https://img.shields.io/badge/license-PolyForm%20NC%201.0.0-blue.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-research--prototype-orange.svg)](https://github.com/fabioschorn/physarum-attack-paths)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/fabioschorn/physarum-attack-paths/releases)
[![CI](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml/badge.svg)](https://github.com/fabioschorn/physarum-attack-paths/actions/workflows/ci.yml)

> **Self-propagating bio-inspired attack-path organism for controlled security research.** `physarum-attack-paths` is a Rust research prototype that turns local network observations, adaptive sensing, pattern evidence, LLM-driven exploit selection, policy decisions, and cryptographic lineage memory into a living, chain-propagating organism.

<p align="center">
  <img src="assets/branding/physarum-attack-paths-logo-tech-dark.png" alt="Physarum Attack Paths logo" width="600">
</p>

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

The current project focus is the `physarum-maze` organism path: LLM-driven template selection, dynamic vulnerability intelligence, multi-target evidence-driven propagation, and lineage-recorded policy decisions.

| Area | State |
|---|---|
| Rust workspace / protocol foundations | ✔ implemented |
| Adaptive graph scoring (`Q_ij`, `q_ema`, `D_ij`, `/paths`) | ✔ implemented and validated in earlier gates |
| Packet and flow observation (`physarum-ebpf`, packet observers) | ✔ implemented for lab research |
| Native scanner (`physarum-scan` / `physarum-scanner`) | ✔ implemented |
| Structured sensing (`SensingProfile`, `SensingResult`, `PortScan`) | ✔ implemented |
| Adaptive service classification (`ConfirmedWeb`, `LikelyWeb`, `UnknownNeedsMoreSensing`, `ConfirmedNonWeb`) | ✔ implemented |
| Nuclei-compatible native evidence engine (`physarum-spore` / `physarum-sporangium`) | ✔ complete Rust port — all protocols, matchers, extractors, generators (PR #133) |
| Nuclei-legacy template library (13,264 templates baked into Docker image) | ✔ imported and YAML loader implemented (PR #133) |
| Maze organism (`physarum-maze`) | ✔ primary active binary |
| LLM contracts and OpenAI-compatible client (`physarum-llm`) | ✔ implemented and Docker-validated |
| Real LLM Docker Lab | ✔ PF-4 validated |
| Adaptive startup/runtime sensing profiles | ✔ PF-5 / Issue #126 validated (PR #127) |
| Dynamic vulnerability intelligence pipeline (`VulnerabilityIntelService`: LocalAdvisoryCache + OsvFeed) | ✔ PF-5.2 / Issue #131 — real LLM Docker Lab evidence committed (PR #132, #133) |
| PF-6 Phase 1 — LLM two-turn selection, multi-target Docker Lab evidence | ✔ complete via PR #140 (host-a/host-b/host-c) |
| PF-6 Phase 2 — ephemeral-key SCP propagation and lineage continuation | ✔ complete — PR #159 (chain: host-a → host-b → host-c → host-d) |
| Issue #144 — Exploit-DB enrichment + `OgnlExec` BootstrapAction, host-d validation | ✔ complete — PR #157 |
| Issue #158 — Propagation bug fixes: lineage-b64 injection, musl static binary, SSH-hang | ✔ complete — PR #159 |
| `physarum-maze` musl static binary (zero glibc dependency — propagation target binary) | ✔ v0.4.0 — `x86_64-unknown-linux-musl` |
| `physarum-maze --server`: live organism API + Leptos WASM real-time graph (Issue #161) | implementation pending |
| Inter-hop evidence relay and D_ij reinforcement via SSH back-channel | brainstorm — planned before Gate N.2 |
| AWS Lab with real LLM | planned — after Gate N |
| Gate N.0 (Issue #89) — secure organism continuity, identity, mTLS, and lineage threat model | next milestone — design only |

The current release line uses these primary binaries:

```text
physarum-maze (x86_64-unknown-linux-gnu)   # organism runtime / evidence loop / lineage — local and CI use
physarum-maze (x86_64-unknown-linux-musl)  # static propagation binary — zero glibc dependency, runs on any Linux target
physarum-scan                              # native scanner binary
physarum-spore                             # native Nuclei-inspired evidence-pattern binary
physarum-sporangium                        # pattern runner / evidence engine crate
```

The musl variant is the binary SCP'd to remote hosts during propagation. It carries no glibc dependency and is self-contained, which is required when the organism hops into heterogeneous targets (e.g. older vulhub images with glibc 2.17–2.28).

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
│  LLM Turn 1 — dynamic template selection                     │
│        │                                                     │
│        ▼                                                     │
│  physarum-spore / physarum-sporangium (HTTP/TCP execution)   │
│        │                                                     │
│        ▼                                                     │
│  PatternFindingSummary                                       │
│        │                                                     │
│        ▼                                                     │
│  VulnerabilityIntelService → vulnerability_candidates        │
│        │                                                     │
│        ▼                                                     │
│  DiscoveryQuery                                              │
│        │                                                     │
│        ▼                                                     │
│  LLM Turn 2a — ordered propagation strategy                  │
│        │                                                     │
│        ▼ (optional enrichment round-trip)                    │
│  LLM Turn 2b — Exploit-DB lookup + OgnlExec delivery         │
│        │                                                     │
│        ▼                                                     │
│  PolicyGate                                                  │
│        │                                                     │
│        ▼                                                     │
│  bootstrap execution (SshCommand / SCP / OgnlExec)           │
│        │                                                     │
│        ▼                                                     │
│  SCP __self__ (musl) → propagated agent (next hop)           │
│        │                                                     │
│        ▼                                                     │
│  LlmAttemptEvidence / lineage (hop recorded)                 │
└──────────────────────────────────────────────────────────────┘
```

### Component roles

| Component | Role |
|---|---|
| `physarum-maze` | Organism controller/runtime: seed/propagated behavior, two-turn LLM evidence loop (Turn 2a + optional Turn 2b enrichment), policy-gated propagation, SCP self-replication, chain lineage |
| `physarum-scan` / `physarum-scanner` | Native scanner binary / scanner library — structured sensing profiles |
| `physarum-spore` / `physarum-sporangium` | Evidence-pattern binary / Nuclei-compatible evidence engine used by `physarum-maze` for HTTP and TCP template execution |
| `physarum-llm` | Provider-neutral LLM contracts and clients — `TemplateSelectionQuery`/`Response`, `DiscoveryQuery`, two-turn `PropagationStrategy`, evidence records |
| `VulnerabilityIntelService` | Dynamic vulnerability enrichment layer (LocalAdvisoryCache + OsvFeed) producing `vulnerability_candidates` from observed service/version evidence |
| `PolicyGate` | Local authority and execution boundary — accepts or rejects LLM-proposed strategies before any execution |
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
 4. LLM Turn 1 — dynamic template selection
 5. physarum-sporangium HTTP/TCP template execution
 6. PatternFindingSummary
 7. VulnerabilityIntelService → vulnerability_candidates (first-class stage, not optional)
 8. DiscoveryQuery to LLM
 9. LLM Turn 2a — ordered propagation strategy proposal
10. [optional] LLM Turn 2b — enrichment round-trip: Exploit-DB lookup, OgnlExec delivery generation
11. PolicyGate decision
12. Controlled bootstrap execution (SshCommand, SCP __self__, OgnlExec, FtpModCopy …)
13. SCP musl binary → propagated agent starts on next hop
14. Lineage record (hop recorded, colonized flag, rejected_strategies carried forward)
```

### PF-5.2 — Dynamic vulnerability intelligence pipeline (completed)

Issue #131 (PR #132, #133) implemented and validated the full CVE-aware enrichment pipeline as a first-class stage of the evidence loop — not an optional enrichment:

```text
service/version/banner evidence
  → physarum-spore extracts server version
  → VulnerabilityIntelService (LocalAdvisoryCache 0.85 / OsvFeed 0.75–0.50)
  → vulnerability_candidates in DiscoveryQuery
  → LLM references CVE in reasoning_summary
  → PolicyGate decision recorded in lineage
```

Evidence: `examples/lab-evidence/physarum-lineage-pf52-docker-lab.json` — real GPT-4o-mini run, CVE-2021-23017 correctly matched for nginx/1.18.0.

### PF-6 — End-to-end multi-target Docker Lab

PF-6 proves the full organism pipeline — including LLM-driven template selection and ordered propagation strategy — against genuinely vulnerable, dynamically discovered targets. Design: `General-Docs/PF6_TWO_CONTAINER_END_TO_END_DOCKER_LAB.md`.

The lab topology is multi-target:

```text
host-a — physarum-maze agent (seed)
host-b — Struts target (distinct CVE path)
host-c — ProFTPD / Wing FTP target (distinct CVE paths)
```

**PF-6 Phase 1 (complete via PR #140):** the dynamic pipeline runs end to end with no hardcoded paths — startup sensing discovers host-b/host-c, LLM Turn 1 selects applicable templates, `physarum-sporangium` executes them, `VulnerabilityIntelService` enriches the findings, and LLM Turn 2 proposes an ordered strategy that `PolicyGate` evaluates and lineage records. Evidence: `examples/evidence/pf6-tcp-probing-dualcve-phase1.json` and `examples/lab-evidence/physarum-lineage-pf6-phase1-dryrun-docker-lab.json`.

**PF-6 Phase 2 (complete — PR #159):** validates end-to-end chain propagation through the Phase 1 pipeline with a temporary SSH keypair generated by `host-a`. Only the temporary public key is introduced on the selected target through the approved lab path; the private key never leaves `host-a` and is never sent to the LLM or written to lineage. `host-a` uses SCP with that key to transfer the musl static `__self__` binary and starts the propagated-mode organism. `colonized` is recorded only after real, evidenced success — not a scripted demonstration or marker-file proof.

Chain propagation validated in the four-container lab: `host-a (172.21.0.2) → host-b (.4, hops=0) → host-c (.3, hops=1) → host-d (.5, hops=2)`. The musl static binary is required at each hop because target glibc versions are heterogeneous and unknown in advance. SSH sessions return in under 600 ms via the subshell nohup pattern (`(nohup ... </dev/null >log 2>&1 &)`), which ensures `physarum-maze` is immediately reparented to PID 1 rather than keeping SSH pipe file descriptors open. Evidence: `examples/evidence/pf6-phase2-ephemeral-key-scp-lineage.json`.

### Issue #144 — Exploit-DB enrichment and OgnlExec BootstrapAction (completed)

Issue #144 (PR #157) validated the LLM's ability to autonomously discover exploit techniques via Exploit-DB enrichment and generate an `OgnlExec.commands` array without any hardcoded template or sentinel.

The Exploit-DB CSV (~2 MB compressed) is embedded in the `physarum-maze` binary via `include_bytes!` + zstd decompression, parsed in memory at startup, and made available to the LLM enrichment path. No volumes or external config are required in Docker or AWS deployments.

The four-container lab topology for this validation:

```text
host-a (physarum-maze:lab)             — seed agent, subnet /24 sensing
host-b (physarum-target-pf6:lab)       — Struts 2.5.25  (CVE-2020-17530, HTTP :8080) + sshd
host-c (physarum-target-dualcve:lab)   — ProFTPD 1.3.5 mock (CVE-2015-3306, FTP :21)
                                         Wing FTP 7.4.3 mock (CVE-2025-47812, HTTP :80) + sshd
host-d (physarum-target-ognlexec:lab)  — Struts 2.5.29  (CVE-2021-31805, HTTP :8090) + sshd
                                         OgnlExec target: LLM must query Exploit-DB and generate
                                         commands array autonomously — no hardcoded payloads
```

`PolicyGate` validates the `OgnlExec` action before execution: shell metacharacter injection (`|`, `;`, `&`, backtick) is blocked in every element of `commands`, and the `exploit_enabled` flag must be set in the policy configuration. The Nuclei template library (~300–700 KB compressed) is similarly embedded in the binary and extracted to `/tmp/physarum/templates/` on startup.

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

Local upstream source clones used for analysis (e.g. `nuclei/`) are ignored by `.gitignore` and must not be committed. Native behavior is ported into Rust workspace crates — the Nuclei engine and template library are fully ported into `physarum-sporangium` as of PR #133.

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
| `examples/lab-evidence/physarum-lineage-pf52-docker-lab.json` | PF-5.2 real LLM — CVE-2021-23017 enrichment, full pipeline evidence | ✔ Issue #131 (PR #132, #133) |
| `docker/docker-compose-pf6.yml` + `docker/pf6-lab.sh` | PF-6 Phase 1 — four-container lab, LLM two-turn selection, dual-CVE evidence (host-a/b/c/d) | ✔ complete — PR #140 |
| `docker/pf6-lab.sh --phase2` | PF-6 Phase 2 — chain propagation via ephemeral-key SCP, musl binary, lineage continuation | ✔ complete — PR #159; evidence: `examples/evidence/pf6-phase2-ephemeral-key-scp-lineage.json` |
| `docker/physarum-target-ognlexec.Dockerfile` (host-d) | Issue #144 — LLM Exploit-DB lookup + autonomous OgnlExec delivery against Struts 2.5.29 | ✔ complete — PR #157 |
| `physarum-maze --server` + WASM page (Issue #161) | Live organism graph: seed exposes axum SSE API + Leptos WASM app served from binary; force-directed layout at 60fps | planned — implementation pending |
| Future AWS LLM Lab | Real LLM reasoning in owned AWS lab | planned — after Gate N |
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

### PF-6 Docker Lab: Phase 2 — chain propagation

Phase 2 extends Phase 1 with ephemeral-key SCP propagation. The musl binary is SCP'd to each target and a propagated-mode agent starts on the next hop.

```bash
# Phase 1 only (LLM sensing + exploit selection, no actual propagation)
./docker/pf6-lab.sh

# Phase 2 (requires Manager / policy approval — exploit_enabled=true)
./docker/pf6-lab.sh --phase2
```

Phase 2 produces chain lineage evidence. Validated propagation path: `172.21.0.2 → .4 (hops=0) → .3 (hops=1) → .5 (hops=2)`.

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
| Issue #131 | Dynamic vulnerability intelligence pipeline (LocalAdvisoryCache + OsvFeed) | ✔ PF-5.2 (PR #132, #133) |
| Issue #135 | PF-6 end-to-end Docker Lab design | ✔ done — design complete via #138 |
| Issue #138 | PF-6 design, template catalog, README update | ✔ done |
| Issue #139 | PF-6 YAML templates wired into maze runner + compose/advisory | ✔ done |
| PF-6 Phase 1 | LLM two-turn selection, multi-target dynamic pipeline evidence | ✔ done — PR #140 |
| PF-6 Phase 2 | Ephemeral-key SCP propagation, chain lineage, musl static binary | ✔ done — PR #159 |
| Issue #144 | Exploit-DB enrichment embedded in binary + autonomous `OgnlExec` delivery (host-d) | ✔ done — PR #157 |
| Issue #158 | Propagation bug fixes: lineage-b64 injection, musl binary, SSH-hang root cause | ✔ done — PR #159 |
| Issue #156 | RAG + LLM-generated Nuclei templates with RLEF training loop — brainstorm captured in `INSIGHTS_AND_BRAINSTORM.md` | ✔ closed — PR #162 |
| Issue #161 | `physarum-maze --server`: live organism API (axum/SSE) + Leptos WASM real-time graph visualization — embedded in binary | implementation pending |
| Back-channel | Inter-hop evidence relay and D_ij reinforcement via SSH callback (star topology, port 22 only) | brainstorm — planned before Gate N.2 |
| AWS LLM Lab | Real LLM in owned AWS lab | planned — after Gate N |
| Gate N.0 (Issue #89) | Secure organism continuity, identity, mTLS, and lineage threat model — **design document only, no implementation** | next milestone |

---

## Planned evolution

### v0.4.0 — what is complete

The following milestones were closed in v0.4.0 (current release):

**PF-6 Phase 2 (PR #159)** — chain propagation through the four-container lab with ephemeral-key SCP, musl static binary, and subshell-nohup SSH fix. Validated chain: `172.21.0.2 → .4 → .3 → .5`. `colonized` recorded only after real, evidenced success — not a scripted demonstration.

**Issue #144 (PR #157)** — Exploit-DB CSV (zstd-compressed, embedded via `include_bytes!`) and Nuclei template library (tar.zst, embedded) are both self-contained in the binary. The LLM autonomously queries Exploit-DB at enrichment time and generates an `OgnlExec.commands` array targeting host-d (CVE-2021-31805 / Struts 2.5.29). `PolicyGate` validates each element for shell metacharacter injection before execution.

**Issue #158 (PR #159)** — three propagation bugs fixed: `--lineage-b64` injection into `SshCommand`, musl static binary in Docker builder stage, and the SSH-hang root cause (`&&`-chain child bash entering `do_wait()` with pipe FDs open; fixed by subshell nohup `(nohup ... </dev/null >log 2>&1 &)`).

### Near-term — Issue #161 and back-channel

**Issue #161 — `physarum-maze --server`:** the seed node will expose a live organism graph API (axum + SSE) and serve a Leptos WASM frontend embedded in the binary via `include_bytes!`. The browser page shows each hop colonized in real time, with D_ij edge weights animating as evidence accumulates and node size reflecting LLM confidence. Zero external files — the same binary that propagates also serves the visualization. Validated first in the pf6 Docker lab, then in the AWS lab.

**Back-channel (pre-Gate N.2):** each propagated hop will call back to the seed over SSH port 22 (already open) using an ephemeral callback keypair embedded in the `lineage-b64` payload. The `ColonizationReport` updates D_ij on the seed and feeds the WASM live graph. No extra ports. Gate N.2 will upgrade the transport to mTLS.

### Gate N.0 (Issue #89) — next milestone — design only

Gate N.0 is a **design and threat-model document**. No implementation code is produced until the design is complete. The scope covers:

```text
secure organism continuity and Agent DNA model
node identity bootstrap and certificate/key strategy
TLS vs mTLS scope separation
signed lineage ledger and evidence hash model
Online Cortex Mode and Offline Cortex Capsule Mode trust boundaries
dev/lab mode vs secure mode separation
```

Gate N implementation follows in sub-gates N.1 (Agent DNA), N.2 (mTLS node-to-node), N.3 (signed lineage ledger), N.4 (policy roots), N.5 (cortex mode behavior), N.6 (Docker lab), N.7 (AWS lab).

The AWS controlled LLM Lab (real LLM in an owned EC2/VPC environment) is planned to follow Gate N.

---

## References

1. Tero, A., Kobayashi, R., Nakagaki, T. (2007). *A mathematical model for adaptive transport network in path finding by true slime mold.* Journal of Theoretical Biology, 244(4), 553–564.
2. Becchetti, L., Bonifaci, V., Dirnberger, M., Karrenbauer, A., Mehlhorn, K. (2013). *Physarum can compute shortest paths: convergence proofs and complexity bounds.* ICALP.
3. Liu, Y., Gao, C., Zhang, Z., Lu, Y., Chen, S., Liang, M., Tao, L. (2017). *An improved Physarum polycephalum algorithm for the shortest path problem.* Scientific World Journal.
4. Nakagaki, T., Yamada, H., Tóth, Á. (2000). *Maze-solving by an amoeboid organism.* Nature, 407(6803), 470.
5. Zhao, E., Jia, J., Ba, J., Goldenberg, A., Papernot, N. (2026). *AI Agents Enable Adaptive Computer Worms.* arXiv:2606.03811. University of Toronto / Vector Institute.

For Rust-side dependencies of architectural significance:

- `axum` — HTTP framework for coordinator/API components and the `--server` live graph endpoint (Issue #161)
- `tokio` — async runtime
- `petgraph` — graph data structures
- `aya` — pure-Rust eBPF library
- `clap` — CLI argument parsing
- `reqwest` — HTTP client used by OpenAI-compatible client paths
- `quinn` — QUIC transport *(planned)*
- `ed25519-dalek` — signature scheme *(planned — Gate N)*

---

## License

Licensed under the [PolyForm Noncommercial License 1.0.0](./LICENSE).

This license permits use for any purpose that is **not** primarily intended for commercial advantage or monetary compensation — including academic research, education, and security testing in owned and authorized lab environments.

Commercial use requires a separate agreement. Contact: fabio.schorn@expertsonline.com.br

Patent applications covering methods and systems embodied in this software have been filed by Fábio Schorn. See [NOTICE](./NOTICE) for details.

---

## Contributing

Contributions require signing the Contributor License Agreement (CLA). The CLA bot will guide you through the process on your first pull request.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development workflow, code style, and test requirements. Security issues should be reported according to [SECURITY.md](./SECURITY.md).

---

*"The slime mold has no brain, no nervous system, no central authority. It solves the maze anyway."*

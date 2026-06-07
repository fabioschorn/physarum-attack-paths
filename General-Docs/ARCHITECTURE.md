# System Architecture — Physarum Attack Paths

**Status:** Living authoritative architecture document  
**Last updated:** 2026-06-07  
**Owner:** Project Architecture / Dev Lead

---

## 1. Overview

`physarum-attack-paths` is a Rust research prototype for discovering, evaluating, and recording viable attack paths in owned, isolated, authorized environments. The system borrows the reinforcement-and-decay intuition of *Physarum polycephalum*: useful paths are reinforced, weak or failed paths decay, and lineage preserves the organism's accumulated experience.

The project has evolved through four architectural generations:

```text
Generation 1  coordinator + probing agents + adaptive graph scoring
Generation 2  eBPF / packet observation as runtime stimulus
Generation 3  autonomous physarum-maze propagation in controlled AWS labs
Generation 4  evidence-driven, LLM-assisted, policy-gated organism behavior
```

Generations 1–3 remain valid historical foundations. Generation 4 is the current active architecture.

---

## 2. Safety boundary

The system is intended only for:

```text
- local labs
- Docker labs
- owned AWS lab VPCs
- explicitly authorized research environments
```

It is not intended for public targets, production deployment, Internet scanning, unauthorized exploitation, or unbounded propagation.

The LLM is never the execution authority:

```text
LLM proposes.
PolicyGate decides.
Executor performs only typed, allowed actions.
Lineage records the result.
```

Secrets remain local. API keys and SSH private keys must never appear in prompts, strategy contracts, or lineage.

---

## 3. Current organism architecture

`physarum-maze` is the organism controller and primary active binary.

```text
startup_sensing / ICMP / TCP-eBPF stimulus
  -> physarum-scan / physarum-scanner
  -> SensingResult / PortScan
  -> service classification and version/banner evidence
  -> LLM Turn 1: dynamic template selection
  -> physarum-spore / physarum-sporangium
  -> HTTP/TCP template execution
  -> PatternFindingSummary
  -> VulnerabilityIntelService
  -> vulnerability_candidates
  -> DiscoveryQuery
  -> LLM Turn 2: ordered PropagationStrategy
  -> PolicyGate
  -> typed bootstrap executor
  -> LlmAttemptEvidence / lineage
  -> propagated node, only after real success
```

### 3.1 Component responsibilities

| Component | Responsibility |
|---|---|
| `physarum-maze` | Organism controller/runtime; seed and propagated modes; stimulus handling; two-turn LLM loop; policy-gated execution; lineage |
| `physarum-scan` | Native scanner binary |
| `physarum-scanner` | Scanner library; sensing profiles; port/service/banner/version evidence |
| `physarum-spore` | Evidence-pattern CLI |
| `physarum-sporangium` | Nuclei-compatible Rust evidence engine; builtin and `nuclei-legacy` templates; HTTP/TCP/DNS/SSL/WebSocket/workflow support |
| `VulnerabilityIntelService` | Enriches findings through `LocalAdvisoryCache`, `OsvFeed`, affected-version ranges, confidence, and vulnerability sources |
| `physarum-llm` | Provider-neutral contracts and clients; template-selection and propagation-reasoning queries; OpenAI-compatible and mock paths |
| `PolicyGate` | Local authority boundary for CIDR, confidence, attempts, method class, and lab-only exploit controls |
| `physarum-ebpf` / packet observers | Runtime TCP/ICMP/flow stimuli in controlled labs |
| `physarum-probe` | Earlier graph/probe execution primitives |
| `physarum-agent` / `physarum-server` | Historical coordinator-oriented adaptive graph architecture |
| `formal/tla` | Formal models for scoring and path-safety properties |

### 3.2 Crate layout

```text
crates/
  physarum-protocol
  physarum-server
  physarum-agent
  physarum-probe
  physarum-node
  physarum-node-runtime
  physarum-scanner
  physarum-scan
  physarum-sporangium
  physarum-spore
  physarum-llm
  physarum-maze
  physarum-ebpf-observer
  physarum-ebpf-observer-ebpf
  physarum-packet-observer
  physarum-packet-observer-ebpf
```

---

## 4. Mathematical foundation

The earlier graph architecture maintains per-edge signals:

```text
Q_ij   instantaneous probe quality
q_ema  smoothed quality
D_ij   persistent conductivity / edge weight
```

The negative-log path score used from Gate K.1 onward is:

```text
score(p) = exp(-(sum(-ln(max(q_ema_i, Q_EMA_FLOOR))) + HOP_WEIGHT * (k - 1)))
```

The autonomous maze lineage also records reinforcement and decay semantics for productive hops, dead ends, already-colonized nodes, and secondary conduits. These models remain relevant as graph memory even while the current active loop is evidence-driven.

---

## 5. Generation 1 — coordinator and probing agents

Generation 1 established:

```text
physarum-agent -> ProbeReport -> physarum-server -> adaptive graph
```

Validated work includes local and Docker graph labs, AWS full-mesh and segmented labs, weighted competing paths, `tc/netem`, and TLA+ safety checks.

This generation remains historical and is not the primary organism path.

---

## 6. Generation 2 — passive runtime observation

Generation 2 introduced packet and eBPF observations:

```text
TCP/ICMP/flow event -> FlowObservation / stimulus -> discovery or scoring loop
```

The eBPF path captures metadata only. It does not copy packet payloads.

Validated work includes Gates I, J, J.1, K, and K.1.

---

## 7. Generation 3 — autonomous maze propagation

Generation 3 introduced `physarum-maze` and proved autonomous propagation in the controlled PF-1 and PF-2 AWS labs.

### 7.1 Historical PF-1/PF-2 mechanism

The PF-1/PF-2 labs used preconfigured, lab-only SSH behavior, including empty-password SSH in the isolated topology, to copy and start the binary remotely.

```text
SCP physarum-maze -> target
SSH/systemd-run -> start remote maze
lineage -> record path, hops, visited, colonized, scores, conduits
```

This mechanism is preserved as historical evidence. It is not the current PF-6 mechanism.

### 7.2 Validated behavior

PF-1 proved organic expansion through a seven-node AWS maze. PF-2 proved adaptive re-routing, delayed nodes, TCP stimulus, already-colonized handling, and secondary conduits in a nine-node topology.

---

## 8. Generation 4 — LLM-aware evidence-driven organism

Generation 4 is implemented and active.

### 8.1 PF-4 — real LLM integration

PF-4 validated an OpenAI-compatible endpoint in Docker and proved:

```text
DiscoveryQuery -> real LLM -> PropagationStrategy -> PolicyGate -> lineage
```

### 8.2 PF-5 — adaptive sensing

PF-5 introduced trigger-aware sensing:

| Trigger | Profile | Semantics |
|---|---|---|
| startup | `StartupLocalDiscovery` | local subnet discovery; starts without an external ping harness |
| ICMP | `RuntimeIcmpFast` | fast common-port profile |
| TCP/eBPF | `RuntimeTcpEbpfFast` | fast no-host-discovery profile |
| enrichment | `ServiceVersion` | deeper service/version evidence |

Automatic interface selection now chooses the interface matching the allowed lab CIDR.

### 8.3 PF-5.2 — dynamic vulnerability intelligence

PF-5.2 added:

```text
PatternFinding
  -> VulnerabilityIntelService
  -> LocalAdvisoryCache / OsvFeed
  -> affected-version evaluation
  -> vulnerability_candidates
  -> DiscoveryQuery
```

This is a first-class stage, not an optional fixture.

### 8.4 Nuclei-compatible evidence engine

`physarum-sporangium` contains the Rust implementation and the canonical `nuclei-legacy` template catalog. It supports the protocol, matcher, extractor, workflow, payload, and authentication capabilities documented in `SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md`.

The LLM receives compact template metadata, not unrestricted template bodies or arbitrary shell authority.

### 8.5 PF-6 Phase 1 — completed

PR #140 completed the current multi-target Docker evidence loop:

```text
host-a  physarum-maze seed
host-b  Struts target path
host-c  ProFTPD / Wing FTP target paths
```

Phase 1 proved:

```text
- dynamic discovery of multiple targets
- web and non-web service probing
- LLM Turn 1 template selection
- HTTP/TCP template execution
- vulnerability-candidate enrichment
- LLM Turn 2 ordered strategy reasoning
- PolicyGate behavior
- lineage evidence and retries
```

No target IP, CVE, template, finding, or policy result may be hardcoded into the organism control path.

### 8.6 PF-6 Phase 2 — active, Issue #141

Phase 2 reuses the unchanged Phase 1 pipeline and validates the already-selected propagation mechanism:

```text
1. host-a generates a temporary SSH keypair.
2. Only the public key is introduced on the dynamically selected target through the approved lab path.
3. The private key remains local to host-a and never reaches the LLM or lineage.
4. SCP transfers the current `__self__` physarum-maze binary.
5. SSH starts the target in propagated mode.
6. The propagated node continues the original lineage.
7. `colonized` is recorded only after real SCP, SSH, and startup success.
8. Temporary key material is removed on success, failure, timeout, or cleanup.
```

Issue #141 is the authoritative acceptance gate. The Docker proof must remain generic enough to be adapted to the controlled AWS Lab without a separate fake or target-specific implementation.

---

## 9. LLM contracts and execution boundary

The LLM flow is split into two turns.

### Turn 1 — template selection

Input includes observed ports, protocol/service hints, banner/version evidence, and compact template metadata.

Output is a typed set of selected template IDs and selection reasoning.

### Turn 2 — propagation reasoning

Input includes findings, vulnerability candidates, prior rejections, source information, the temporary public key when applicable, and lineage context.

Output is a typed `PropagationStrategy` with an ordered `BootstrapPlan`.

### Policy and secrets

```text
- exploit-class behavior is disabled by default
- Phase 2 must be explicitly enabled
- CIDR allowlist and confidence thresholds remain mandatory
- arbitrary `Custom` execution is disabled by default
- private keys and API tokens never enter contracts or lineage
- executor resolves local secret references at runtime
```

---

## 10. Gate progression

| Gate / phase | Status |
|---|---|
| A–K.1 | completed |
| L / L.1 / L.2 / L.3 | completed |
| M / M.4 | completed |
| PF-1 | completed |
| PF-2 | completed |
| PF-4 | completed |
| PF-5 | completed |
| PF-5.2 | completed |
| PF-6.0 documentation/design | completed via #138 |
| PF-6.1 Phase 1 multi-target evidence | completed via #139/#140 |
| PF-6.2 ephemeral-key SCP propagation | active — Issue #141 |
| controlled AWS LLM Lab | planned after #141 |
| Gate N identity/mTLS/signed lineage | planned |

---

## 11. Build and deployment

Local `cargo` builds are acceptable for development. Lab artifacts deployed to AWS must use the project Docker Build Cloud process and must be destroyed after each controlled run.

The current Docker PF-6 runner is:

```bash
docker/pf6-lab.sh
docker/pf6-lab.sh --phase2
```

Phase 2 remains opt-in.

---

## 12. Documentation authority

| Document | Authority |
|---|---|
| `README.md` | project front door and concise current status |
| `General-Docs/ARCHITECTURE.md` | authoritative system design |
| `General-Docs/QUALITY_GATE.md` | current advancement decision and evidence state |
| `General-Docs/PF6_TWO_CONTAINER_END_TO_END_DOCKER_LAB.md` | PF-6 topology, invariants, and run model |
| `General-Docs/SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md` | template engine and LLM integration model |
| `crates/physarum-llm/DESIGN.md` | LLM contract decisions and phase state |
| GitHub Issues/PRs | detailed historical delivery and runtime evidence |

Detailed issue history belongs in GitHub, not duplicated throughout the architecture document.
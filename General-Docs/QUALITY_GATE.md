# Quality Gate — Physarum Attack Paths

**Current gate:** PF-2 — Adaptive Re-routing — COMPLETE  
**Overall status:** GREEN through PF-2  
**Last updated:** 2026-05-25

> GREEN = ready to advance · YELLOW = usable, follow-up required · RED = blocked or unstable · FUTURE = planned, not blocking current gate

---

## Current decision

The project has completed the component gates through Gate M and the pre-final organism labs PF-1/PF-2.

```text
Gate M      COMPLETE — physarum-node runtime convergence
Gate M.4    COMPLETE — probe/discovery consolidation and scoring adapter
PF-1        COMPLETE — organic expansion maze
PF-2        COMPLETE — adaptive re-routing, TCP stimulus, AlreadyColonized, secondary conduits
```

The next implementation/design direction is intentionally narrow:

```text
1. Issue #106 — physarum-llm design/safety review for the Causal Continuity Paradox
2. Issue #89 / Gate N.0 — secure organism identity, mTLS, and signed lineage after #106
```

---

## Gate checklist

| Area | Status | Evidence | Notes |
|---|---|---|---|
| Build / test health | GREEN | CI / cargo workspace tests | Workspace builds and tests pass at completed gate points |
| Documentation workflow | GREEN | PR/issue templates + ownership guidelines | Documentation ownership model merged |
| Formal model — single edge | GREEN | `PhysarumEdgeModel.tla` | TypeOK + Safety verified |
| B/C/D TLA+ path-selection model | GREEN | PR #56 | TypeOK + Safety + PathSelectionSafety verified |
| Gate I — FlowObservation model and API | GREEN | PR #68 | `POST /flow-observations`, `GET /flow-observations`, bounded buffer, tests |
| Gate J — eBPF observer runtime | GREEN | Issue #69 | AWS EC2 kernel 6.18; tracepoint attached; metadata-only observation |
| Gate J.1 — eBPF observer agent-flow correlation | GREEN | Issue #72 | 5-tuple confirmed for physarum probe flow |
| Gate K — segmented adaptive flow-path lab | GREEN | Issue #76 | 5-node AWS lab, q_ema degradation/recovery, FlowObservation evidence |
| Gate K.1 — autonomous path selection | GREEN | Issue #80 / PR #82 | Negative-log scoring, selected_path, secondary_conduits |
| Gate L — `physarum-scanner` native discovery engine | GREEN | commit `ce2b537` | Native async discovery, CIDR/DNS resolution, port ordering, resource-limit handling |
| Gate L.1 — eBPF-triggered adaptive discovery | GREEN | `ebpf-triggered-discovery-evidence.txt` | Trigger provenance and priority ordering confirmed |
| Gate L.2 — local-interface scope + inbound eBPF discovery | GREEN | `gate-l2-local-interface-evidence.txt` | Local subnet scope and inbound host discovery validated |
| Gate L.3 — ICMP packet-level stimulus sensing | GREEN | Issue #87 | `physarum-packet-observer` ICMP stimulus evidence |
| Gate M — `physarum-node` runtime | GREEN | `gate-m-node-runtime-evidence.txt` | `physarum-node` supervises agent and observer children |
| Gate M.4 — scoring adapter / probe consolidation | GREEN | PR #102 | probe/discovery internalized through `physarum-probe`; agent wrapper retained |
| PF-1 — organic expansion maze | GREEN | PR #104 / `ansible-pf1/` | 7-node AWS lab, autonomous SCP+SSH propagation, lineage |
| PF-2 — adaptive re-routing | GREEN | PR #104 / `ansible-pf2/` | 9-node AWS lab, lateral discovery, TCP stimulus, AlreadyColonized, secondary conduits |
| `physarum-llm` | FUTURE | Issue #106 | Planned research/design track |
| Gate N.0 — secure organism identity | FUTURE | Issue #89 | Planned after Issue #106 |
| Security hardening / API auth | FUTURE | — | Coordinator API remains unauthenticated; lab access must stay restricted |

---

## PF-2 final evidence summary

**GREEN** for PF-2 — Adaptive Re-routing.

Validated topology:

```text
A      seed, front subnet 10.60.10.0/24
A.1    lateral node, same subnet as A, appears after delay
B/C    layer-1 subnet 10.60.20.0/24
D/E/F  layer-2 subnet 10.60.30.0/24
G      layer-3 milestone 10.60.40.0/24
X      cross-subnet node 10.60.50.0/24, appears after delay
```

Validated adaptive behaviors:

```text
1. A discovers A.1 through /24 physarum-scanner discovery.
2. X sends TCP SYN stimulus to A.1:22 through bash /dev/tcp.
3. A.1 captures the TCP stimulus, discovers X, and propagates to X.
4. X detects G as already colonized.
5. G is not re-deployed.
6. X records X→G as a secondary conduit.
7. Terraform destroy completed; no persistent AWS lab resources remain.
```

Live-run fixes documented in PR #104:

```text
nc replaced with bash /dev/tcp because nc was absent on AL2023
ICMP verification changed to journal-based evidence because SG rules are directional
operator IP masked as <OPERATOR_IP>
```

---

## PF-1 final evidence summary

**GREEN** for PF-1 — Organic Expansion Maze.

Validated behavior:

```text
single seed starts at Host A
organism discovers candidates from bounded stimuli
organism propagates through the maze by SCP + SSH in the controlled AWS lab
lineage JSON records origin, path, hops, visited nodes, scores, and colonized hosts
G is reached without predefining G as a final target
```

Validated path:

```text
A → C → E → F → G
```

Dead-end behavior:

```text
D scored as a dead end and decayed through the per-edge multiplier model
```

---

## Gate progression summary

| Gate | Description | Status |
|---|---|---|
| A | S3 artifact delivery + EC2 bootstrap design | COMPLETED |
| B | S3 delivery + IAM role + user_data | COMPLETED |
| C | AWS Mode 1 full mesh runtime | COMPLETED |
| D | Phase identity (`lab_phase` variable) | COMPLETED |
| E | AWS Mode 2 segmented B→C→D | COMPLETED |
| F | B/C/D TLA+ path-selection model | COMPLETED |
| G | Docker weighted competing paths | COMPLETED |
| H | AWS tc/netem weighted competing paths | COMPLETED |
| I | FlowObservation model + POST/GET endpoints | COMPLETED |
| J | eBPF observer runtime on AWS EC2 | COMPLETED |
| J.1 | eBPF observer agent-flow correlation | COMPLETED |
| K | Segmented adaptive flow-path lab | COMPLETED |
| K.1 | Autonomous path selection with negative-log scoring | COMPLETED |
| L | `physarum-scanner` native discovery engine | COMPLETED |
| L.1 | eBPF-triggered adaptive discovery | COMPLETED |
| L.2 | Local-interface scope + inbound eBPF discovery | COMPLETED |
| L.3 | ICMP packet-level stimulus sensing | COMPLETED |
| M | `physarum-node` runtime convergence | COMPLETED |
| M.4 | Probe/discovery consolidation and scoring adapter | COMPLETED |
| PF-1 | Organic expansion maze | COMPLETED |
| PF-2 | Adaptive re-routing | COMPLETED |
| Issue #106 | LLM-aware adaptive propagation design | PLANNED |
| Gate N.0 / Issue #89 | Secure organism identity, mTLS, and lineage threat model | PLANNED |

---

## Active gate

No active implementation gate.

The active planning sequence is:

```text
Issue #106 first
Gate N.0 / Issue #89 after #106
```

Reason:

```text
Issue #106 may change the organism's future propagation surface.
Gate N.0 must model secure identity, mTLS, and signed lineage after that surface is clarified.
```

---

## Open blockers

```text
coordinator API remains unauthenticated
operator_cidr must remain a narrow /32 in AWS labs
node identity is not yet mTLS-backed
lineage is structured but not yet cryptographically signed
```

---

## Known risks

```text
AWS work may introduce infrastructure complexity if started before scope is agreed
documentation can drift if QUALITY_GATE.md or ARCHITECTURE.md start accumulating issue history (that belongs in GitHub Issues/PRs)
operator_cidr must remain a narrow /32 until coordinator API authentication is added
arm64 binary cross-compilation requires additional CI/toolchain setup if Graviton is revisited
latency-based quality discrimination requires real network or tc/netem; Docker localhost RTTs are too similar
future LLM-assisted propagation must stay lab-only and safety-gated unless separately approved
```

---

## Project quality rules

```text
Design before implementation
Runtime validation before merge
Docs describe only what is currently implemented
One primary doc file per feature PR
GitHub Issues/PRs are the detailed historical record
```

See [General-Docs/DOCUMENTATION_GUIDELINES.md](DOCUMENTATION_GUIDELINES.md) for the full documentation ownership model.

---

## How to read this page

This page answers: **are we ready for the next phase?**

```text
All relevant rows GREEN  -> advance
Any row YELLOW           -> close follow-up before advancing
Any row RED              -> stop and fix the blocker first
FUTURE rows              -> visible but non-blocking
```

For detailed validation output, issue history, and delivery notes, use the linked GitHub Issues and PRs. For the current system description, use [General-Docs/ARCHITECTURE.md](ARCHITECTURE.md).

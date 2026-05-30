# wasm-lab — Future Visualization and Simulation Idea

> **Status:** Research/backlog idea only. No active implementation gate. Not part of the current roadmap.

This document captures the idea of a browser-based visual simulator for the adaptive graph model at the core of `physarum-attack-paths`. The idea remains valid and worth preserving, but implementation has not been started and is not planned in the near term.

---

## Purpose

The wasm-lab would make the organism's edge dynamics visible and interactive — for research demonstrations, architecture discussions, and onboarding.

It does not replace the Docker lab or the AWS lab:

```text
Docker lab = reproducible runtime test (complete)
AWS lab    = realistic VPC network validation (PF-1 and PF-2 complete)
wasm-lab   = visual model explanation and simulation (not yet implemented)
```

---

## What has been validated so far

The following labs are complete and validate real behavior:

```text
PF-1 — organic expansion maze across real EC2/VPC topology
PF-2 — adaptive re-routing when a secondary conduit appears
physarum-llm — Phase 1 contracts for LLM-aware propagation reasoning
```

The wasm-lab would visualize the same mathematical model that these labs validate at runtime. It is complementary, not a prerequisite.

---

## What a wasm-lab would demonstrate

### Single-edge simulator (first target)

The core idea is a browser widget where a user adjusts input parameters and observes how a single directed edge evolves:

```text
Inputs:
  success_rate
  avg_rtt_ms
  jitter_ms
  EMA alpha
  D_ij decay rate
  number of simulation steps

Computed values:
  latency_score
  Q_ij
  q_ema
  D_ij

Visual output:
  line charts of Q_ij, q_ema, D_ij over time
  simple graph view: agent-b -> agent-c
  edge state label
```

### Mathematical model to simulate

**Latency score:**
```text
latency_score = 1.0 / (1.0 + avg_rtt_ms / 100.0)
```

**Normalized stimulus:**
```text
if success_rate = 0.0: Q_ij = 0.0
else: Q_ij = clamp(0.7 * success_rate + 0.3 * latency_score, 0.0, 1.0)
```

**EMA update:**
```text
q_ema(t+1) = alpha * Q_ij + (1.0 - alpha) * q_ema(t)
q_ema(0) = 0.0
```

**Conductivity update:**
```text
f(x) = x² / (1 + x²)
D_ij(t+1) = D_ij(t) + f(q_ema) * (1 - D_ij(t)) - decay_rate * D_ij(t)
D_ij(0) = 0.0, clamped to [0.0, 1.0]
```

---

## Staged implementation idea

If this ever moves from backlog to an active issue, a staged approach is recommended:

| Stage | Scope |
|---|---|
| v0 | Single-edge Q_ij / q_ema / D_ij simulator with sliders and line charts |
| v1 | Small graph replay (3–4 nodes) with path scoring preview |
| v2 | PF-1/PF-2 lineage JSON replay — animate the organism's actual expansion |
| v3 | physarum-llm decision-loop visualization, only after that path is stable |

v3 is explicitly deferred until the physarum-llm integration (Issue #106, Phase 4+) is complete and stable.

---

## Technology options (for reference)

If implemented, the simplest first approach would be:

```text
wasm-bindgen — expose Rust functions for Q_ij, q_ema, D_ij updates
Plain HTML/CSS/JS — sliders and layout
Chart.js or SVG — line charts
```

More structured Rust-first options if the UI grows:

```text
Leptos or Yew — Rust component framework
Trunk — simple WASM build workflow
```

No decision has been made. This is captured for when the issue is opened.

---

## Relationship to other docs

- [`General-Docs/INSIGHTS_AND_BRAINSTORM.md §11`](../../General-Docs/INSIGHTS_AND_BRAINSTORM.md) — records this idea in the project's backlog
- [`General-Docs/ARCHITECTURE.md`](../../General-Docs/ARCHITECTURE.md) — describes the Q_ij / q_ema / D_ij model as implemented
- [`examples/aws-lab/`](../aws-lab/) — the active AWS/VPC lab (PF-1, PF-2 complete)

---

## Out of scope for any wasm-lab version

```text
real networking or live server connections
Docker Compose or Terraform
AWS infrastructure
agent deployment
eBPF
mTLS or Ed25519
persistence or lineage writing
production UI
```

The wasm-lab is and will remain a pure simulation and visualization tool.

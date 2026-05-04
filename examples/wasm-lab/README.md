# WASM Lab — Future Visual Simulation Lab

This document captures a future idea for a Rust + WebAssembly visual laboratory for `physarum-attack-paths`.

The WASM lab is not intended to replace the Docker lab or the AWS lab.

Instead, it should become an interactive browser-based simulator for explaining, visualizing, and experimenting with the mathematical core of the project:

```text
local observation window -> enriched ProbeReport -> Q_ij -> q_ema -> D_ij
```

---

## 1. Purpose

The purpose of the WASM lab is to make the adaptive edge dynamics visible.

The Docker lab proves that the real server and agents run together.
The AWS lab will eventually prove behavior across realistic EC2/VPC network boundaries.
The WASM lab should help humans understand the model.

Recommended positioning:

```text
Docker lab = reproducible runtime test
AWS lab    = realistic network test
WASM lab   = visual model/simulation test
```

---

## 2. What the WASM lab should demonstrate

The first visual demo should focus on a single directed edge:

```text
agent-b -> agent-c
```

The user should be able to adjust input parameters and observe how the edge changes over time.

Inputs:

```text
success_rate
avg_rtt_ms
jitter_ms
EMA alpha
D_ij decay rate
number of simulation steps
```

Computed values:

```text
latency_score
Q_ij
q_ema
D_ij
```

Visual output:

```text
line chart of Q_ij over time
line chart of q_ema over time
line chart of D_ij over time
simple graph view showing agent-b -> agent-c
current edge state label
```

---

## 3. Why this is useful

This project is not only a networking tool. It is also a bio-inspired adaptive graph model.

The WASM lab can help explain:

```text
why one successful probe should not dominate the graph
why repeated successful probes reinforce an edge
why sustained failures decay an edge
why q_ema smooths noisy observations
why D_ij behaves like long-term adaptive morphology
why the agent is short-term sensing and the server is long-term memory
```

This is useful for:

```text
research demonstrations
architecture discussions
patent-style explanations
onboarding contributors
validating formulas before implementation
comparing parameter choices
future presentations
```

---

## 4. Initial model to simulate

The first WASM version should implement the same equations used by the server.

### Latency score

```text
latency_score = 1.0 / (1.0 + avg_rtt_ms / 100.0)
```

### Normalized stimulus

If `success_rate = 0.0`:

```text
Q_ij = 0.0
```

Otherwise:

```text
Q_ij = clamp(0.7 * success_rate + 0.3 * latency_score, 0.0, 1.0)
```

### EMA update

```text
q_ema(t+1) = alpha * Q_ij + (1.0 - alpha) * q_ema(t)
```

Initial value:

```text
q_ema(0) = 0.0
```

### Flux function

```text
f(x) = x² / (1 + x²)
```

### Conductivity update

```text
D_ij(t+1) = D_ij(t) + f(q_ema) * (1 - D_ij(t)) - decay_rate * D_ij(t)
```

Initial value:

```text
D_ij(0) = 0.0
```

Clamp:

```text
0.0 <= D_ij <= 1.0
```

---

## 5. Suggested UI concept

A minimal UI could have three panels.

### Panel 1 — Inputs

Controls:

```text
success_rate slider: 0.0 to 1.0
avg_rtt_ms slider: 0 to 1000
jitter_ms slider: 0 to 500
alpha slider: 0.0 to 1.0, default 0.3
decay_rate slider: 0.0 to 1.0, default 0.1
steps slider: 1 to 200
reset button
run simulation button
```

### Panel 2 — Edge state

Display:

```text
Q_ij
q_ema current value
D_ij current value
edge state label: weak / candidate / reinforced / decaying
```

Possible state labels:

```text
D_ij < 0.10         = weak
0.10 <= D_ij < 0.40 = candidate
0.40 <= D_ij < 0.75 = reinforced
D_ij >= 0.75        = dominant
```

These labels are only for visualization and should not become production semantics yet.

### Panel 3 — Charts

Charts:

```text
Q_ij over time
q_ema over time
D_ij over time
```

A future version may show a tiny graph:

```text
agent-b --D_ij/q_ema--> agent-c
```

---

## 6. Possible Rust/WASM technology choices

Recommended simple options:

### Option A — Leptos

```text
Rust-first UI framework
Good for interactive web apps
More structure
```

### Option B — Yew

```text
Mature Rust/WASM frontend framework
Good component model
```

### Option C — wasm-bindgen + plain JavaScript

```text
Smallest initial implementation
Rust exposes calculation functions
JavaScript handles sliders and charts
```

### Option D — Trunk + vanilla Rust frontend

```text
Simple build workflow
Good for small examples
```

Manager recommendation for the first version:

```text
Use the simplest implementation that demonstrates the math clearly.
Do not over-engineer the frontend.
```

A good starting approach may be:

```text
wasm-bindgen for Rust calculations
plain HTML/CSS/JS for UI
Chart.js or SVG for charts
```

---

## 7. Suggested future structure

Possible future structure:

```text
examples/wasm-lab/
├── README.md
├── Cargo.toml
├── src/
│   └── lib.rs
├── web/
│   ├── index.html
│   ├── main.js
│   └── style.css
└── pkg/
```

Alternative if using Trunk:

```text
examples/wasm-lab/
├── README.md
├── Cargo.toml
├── Trunk.toml
├── index.html
└── src/
    └── main.rs
```

---

## 8. Future extension ideas

After the single-edge simulator works, the WASM lab could evolve to:

```text
bidirectional edge simulation: agent-b -> agent-c and agent-c -> agent-b
three-node graph: agent-b -> agent-c -> agent-d
manual failure injection
asymmetric reachability simulation
short-term observation window visualization
path scoring preview
MCPM-inspired stochastic traversal preview
edge/path density animation
```

The most important future demo would be:

```text
A/B/C/D visual attack-path playground
```

Where:

```text
B = perimeter-like node
C = application-like node
D = crown-jewel-like node
```

The user could adjust reachability and stimulus values and see path scores change.

---

## 9. Out of scope for the first WASM lab

Do not include in the first WASM version:

```text
real networking
Docker Compose
AWS infrastructure
Terraform
live server connection
agent deployment
eBPF
mTLS
Ed25519 signatures
persistence
TOON export
production UI
```

The first WASM lab should be a pure simulation/demo of the model.

---

## 10. Relationship to TLA+

TLA+ and WASM serve different purposes.

```text
TLA+ = formal specification and invariant checking
WASM = visual explanation and interactive simulation
```

Both are useful.

A future ideal sequence:

```text
1. Docker lab proves runtime behavior.
2. TLA+ models the edge dynamics invariants.
3. WASM visualizes the same equations for humans.
4. AWS lab validates behavior in real cloud networks.
```

---

## 11. Recommended future issue

Possible future issue title:

```text
Add WASM visual simulator for Q_ij, q_ema, and D_ij edge dynamics
```

Suggested scope:

```text
create examples/wasm-lab Cargo project
expose Rust functions for Q_ij, q_ema, and D_ij updates
build a simple browser UI with sliders
show line charts for q_ema and D_ij
include README instructions to run locally
avoid production UI complexity
```

Acceptance criteria:

```text
user can adjust success_rate and avg_rtt_ms
simulator recomputes Q_ij
simulator shows q_ema over time
simulator shows D_ij over time
D_ij remains clamped to [0.0, 1.0]
README explains that this is a visual simulation, not a deployment lab
```

---

## 12. Manager recommendation

Do not implement this before the Docker lab is complete.

Recommended order:

```text
1. Complete Docker A/B/C lab.
2. Add initial TLA+ edge model.
3. Add WASM visual simulator.
4. Continue toward AWS lab and A/B/C/D path scoring.
```

The WASM lab is valuable because it can make the project's core idea visible:

```text
short-term local stimuli become smoothed graph memory, and graph memory becomes adaptive attack-path morphology.
```

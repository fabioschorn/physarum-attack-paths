# TLA+ Formal Models — Adaptive Edge Dynamics

This directory contains three formal specifications for `physarum-attack-paths`:

| Module | Scope | SCALE (cfg) | Gate |
|---|---|---|---|
| `PhysarumEdgeModel.tla` | Single directed edge — EMA + sigmoid conductivity | 1000 | Phase 1 |
| `PhysarumMultiAgentModel.tla` | Three directed edges: B→C, C→D, B→D — product scoring | 10 | Gate F |
| `PhysarumNegativeLogModel.tla` | Three directed edges — negative-log scoring (Gate K.1) | 10 | Gate K.1 |

---

## 1. What this model represents

`PhysarumEdgeModel.tla` models a **single directed adaptive edge**:

```
source  ->  target
```

It captures the core signal pipeline that drives adaptive morphology in the system:

```
ProbeReport  ->  Q_ij  ->  q_ema  ->  D_ij
```

| Symbol    | Meaning                                                  |
|-----------|----------------------------------------------------------|
| `Q_ij`    | Normalized stimulus signal computed from a probe report  |
| `q_ema`   | Exponential moving average of Q_ij (smoothed signal)     |
| `D_ij`    | Physarum conductivity — the adaptive weight of the edge  |

The state variables are `q_ema` and `d_ij`.  The model is non-deterministic over
the set of discrete probe report classes `{SuccessfulFast, PartialSuccess, Failed}`.

---

## 2. Why TLA+

TLA+ lets us:

- Express the mathematical update rules as a state machine independently of
  the Rust implementation;
- Check **boundedness invariants** (`q_ema` and `d_ij` stay in `[0, SCALE]`)
  for all reachable states and all possible sequences of probe reports;
- Provide a language-agnostic reference for the adaptive morphology loop that
  any future implementation can be compared against.

We are not trying to verify the full distributed protocol here.  The goal is to
lock down the mathematical heart of the adaptive edge so future changes cannot
silently break the core invariants.

---

## 3. Intentional simplifications

| Aspect                          | Runtime behaviour                        | Model simplification                                |
|---------------------------------|------------------------------------------|-----------------------------------------------------|
| `success_rate`                  | Float in `[0.0, 1.0]`                   | Encoded implicitly in discrete report class          |
| `avg_rtt_ms`                    | Continuous millisecond value             | Three latency classes: Fast / Partial / Failed       |
| `latency_score`                 | `1 / (1 + avg_rtt_ms / 100)`            | Pre-computed per report class                        |
| Floating-point arithmetic       | IEEE 754 double precision               | Scaled integers with truncating integer division     |
| Coordinator and agent processes | Distributed state machine                | Not modelled (single-edge only)                      |
| Network topology                | Graph of N agents                        | Not modelled                                         |
| Observation window (VecDeque)   | 20-sample sliding window in the agent   | Not modelled (inputs arrive as abstract report types)|

The first model is intentionally minimal.  It does **not** model:
- Agent D, multiple edges, or the coordinator's graph state
- The `/paths`, `/path-density`, or MCPM traversal endpoints
- Persistence, mTLS, eBPF, or AWS infrastructure

---

## 4. Scaled integer arithmetic

TLC does not handle arbitrary floating-point arithmetic.  All real-valued
quantities in `[0.0, 1.0]` are represented as integers in `[0, SCALE]`.

With `SCALE = 1000`:

```
1.0   ->  1000
0.7   ->   700
0.3   ->   300
0.0   ->     0
```

The derived scaling coefficients are:

| Constant    | Value (SCALE=1000) | Represents |
|-------------|-------------------|------------|
| `Alpha`     | 300               | EMA weight α = 0.3 |
| `OneAlpha`  | 700               | 1 − α = 0.7 |
| `WSuc`      | 700               | Q_ij weight for success_rate |
| `WLat`      | 300               | Q_ij weight for latency_score |
| `Decay`     | 100               | Conductivity decay rate 0.1 |

All divisions use **integer truncation** (`\div` in TLA+).  This introduces a
small rounding error relative to the IEEE 754 runtime, but the key properties
— monotonicity and boundedness — are preserved.

### Known artefact of integer division

For very small `d_ij` values (< 10), `Decay * d_ij \div SCALE` evaluates to 0
due to truncation, so decay effectively stops before `d_ij` reaches 0.  This
means `d_ij` can become stuck at a small positive value under sustained failure,
rather than converging to exactly 0.  The **boundedness invariant still holds**
(`d_ij >= 0`), and the behaviour is documented here so TLC results are not
misinterpreted.

### Theoretical equilibrium (for reference)

Under `SuccessfulFast` reports exclusively (success_rate = 1.0, fast latency):

```
Q_ij  = 1.0  -> 1000
q_ema -> 1.0  -> 1000  (EMA convergence)
f(1)  = 0.5
D*    = f(1) / (f(1) + decay) = 0.5 / 0.6 = 5/6 ≈ 0.833  -> 833
```

Under sustained `Failed` reports:

```
Q_ij  = 0
q_ema -> 0
f(0)  = 0
D_ij decays via -decay * D_ij, approaching 0
```

---

## 5. How to run the model with TLC

### Prerequisites

Install the TLA+ Toolbox or download `tla2tools.jar` from
https://github.com/tlaplus/tlaplus/releases.

### Command-line invocation

From the repository root:

```bash
cd formal/tla
tlc PhysarumEdgeModel.tla -config PhysarumEdgeModel.cfg
```

Or using the JAR directly:

```bash
java -jar /path/to/tla2tools.jar PhysarumEdgeModel.tla -config PhysarumEdgeModel.cfg
```

### Expected output

TLC should report something like:

```
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = ...
  based on the actual fingerprint population: val = ...
<Number> states generated, <Number> distinct states found, 0 states left on queue.
The depth of the complete state graph search is <N>.
Finished in <time>.
```

If TLC finds a violation of `Safety` or `TypeOK`, it will print a
counterexample trace showing the sequence of report types that led to the
invariant breach.

### Performance note

With `SCALE = 1000`, the reachable state space is a subset of
`[0..1000] × [0..1000]` (about 10⁶ possible states).  TLC explores only the
reachable states from `Init`, which is substantially smaller.  Checking
typically completes in seconds to a few minutes depending on hardware.

For faster iteration during development, set `SCALE = 10` in
`PhysarumEdgeModel.cfg`.  The invariants still hold and TLC finishes
instantly, though the integer-rounding artefacts are more pronounced.

---

## 6. Invariants checked by TLC

| Invariant      | Property                                            |
|----------------|-----------------------------------------------------|
| `TypeOK`       | `q_ema ∈ 0..SCALE ∧ d_ij ∈ 0..SCALE`               |
| `QEmaBounded`  | `q_ema >= 0 ∧ q_ema <= SCALE`                       |
| `DijBounded`   | `d_ij >= 0 ∧ d_ij <= SCALE`                         |
| `Safety`       | `QEmaBounded ∧ DijBounded` (combined, checked by TLC)|

These invariants confirm that:

- `q_ema` and `d_ij` never go negative regardless of the probe sequence;
- `q_ema` and `d_ij` never exceed `SCALE` (= 1.0 in real terms);
- sustained failure cannot drive `d_ij` below 0;
- successful reports keep `q_ema` above 0 (observable in TLC traces).

---

## 7. Formal coverage vs. runtime evolution

The three models together cover the mathematical heart of the scoring pipeline
through Gate K.1.  Elements of the runtime that are **not yet formally modelled**:

| Runtime element | Status |
|---|---|
| Multiple agents, concurrent message-passing delays | Not modelled |
| Coordinator graph state and probe scheduling | Not modelled |
| 20-sample VecDeque observation window per peer | Not modelled |
| physarum-maze multiplier scoring (×1.5/×0.05/×0.8/×1.2, PF-1/PF-2) | Not modelled |
| Secondary conduit detection and lineage recording | Not modelled |
| physarum-scanner /24 discovery loop and stimulus prioritisation | Not modelled |
| Causal Continuity Paradox resolution via physarum-llm (Issue #106) | Future formal work |
| `/path-density` endpoint and MCPM-inspired stochastic traversal | Future formal work |

The current models isolate the adaptive edge dynamics so they can be verified
and kept stable as the system grows around them.

---

## 8. Multi-agent model — `PhysarumMultiAgentModel.tla`

### 8.1 What it models

`PhysarumMultiAgentModel.tla` extends the single-edge model to the three
directed edges relevant to path selection from agent-b to agent-d in the
B/C/D lab topology:

```
B -> C   (edge bc)
C -> D   (edge cd)
B -> D   (edge bd — direct path, degraded in Mode 2)
```

Each edge carries its own `(q_ema, d_ij)` pair, evolved by the same
pipeline as `PhysarumEdgeModel.tla`.  At each step, one edge
non-deterministically receives a probe report; the other two are unchanged.

This is a scoped formal model of the B→D path-selection property over three
directed edges.  It is not a full formal model of all runtime behaviour.

### 8.2 State variables

| Variable | Edge | Meaning |
|---|---|---|
| `q_ema_bc`, `d_ij_bc` | B→C | EMA signal and conductivity for edge B→C |
| `q_ema_cd`, `d_ij_cd` | C→D | EMA signal and conductivity for edge C→D |
| `q_ema_bd`, `d_ij_bd` | B→D | EMA signal and conductivity for edge B→D (direct) |

### 8.3 Invariants

| Invariant | Property |
|---|---|
| `TypeOK` | All 6 variables ∈ 0..SCALE |
| `Safety` | All 6 variables bounded in [0, SCALE] — verified simultaneously across all edges |
| `PathSelectionSafety` | When `d_ij_bd = 0` and `PathScoreBCD > 0`, the indirect path B→C→D outscores the direct path B→D |

`PathSelectionSafety` formalises the Mode 2 segmentation observation:

```
PathScoreBD  = d_ij_bd
PathScoreBCD = d_ij_bc × d_ij_cd ÷ SCALE

(d_ij_bd = 0 ∧ PathScoreBCD > 0) ⇒ PathScoreBCD > PathScoreBD
```

The guard `PathScoreBCD > 0` is required because integer division
truncates `d_ij_bc × d_ij_cd ÷ SCALE` to 0 when both edge conductivities
are very small (e.g., both = 1 with SCALE = 10).  Those degenerate states
are excluded — the invariant covers all states where the indirect path has
meaningful conductivity.

`PathSelectionSafety` formalises the binary Mode 2 case (blocked direct
edge vs. live indirect path).  Weighted competing paths with multiple
positive alternatives are tracked separately in Issue #52.

> **Scoring model note:** `PathScoreBCD` uses the original
> product-of-conductivities formula (`d_ij_bc × d_ij_cd ÷ SCALE`).
> The runtime `/paths` endpoint uses negative-log scoring since Gate K.1:
> `score = exp(-(Σ -ln(max(q_ema_i, 0.001)) + 0.05×(k-1)))`.
> The Mode 2 property (blocked direct edge cannot outscore a live indirect
> path) holds under both formulas.  The negative-log model is formalised
> separately in `PhysarumNegativeLogModel.tla` (section 9).

### 8.4 SCALE = 10

With `SCALE = 10`, each of the six variables has 11 possible values:

```
State-space upper bound: 11^6 = 1,771,561 (6 variables × 11 values each)
Distinct states reachable from Init:        148,877
```

TLC exhaustive checking completes in seconds.  The integer-rounding
artefact documented in section 4 (decay stalls before d_ij reaches 0)
applies to all three edges equally.

### 8.5 How to run

```bash
cd formal/tla
tlc PhysarumMultiAgentModel.tla -config PhysarumMultiAgentModel.cfg
```

Or using the JAR:

```bash
java -jar /path/to/tla2tools.jar PhysarumMultiAgentModel.tla -config PhysarumMultiAgentModel.cfg
```

Expected output:

```
Model checking completed. No error has been found.
  ...
<N> states generated, <N> distinct states found, 0 states left on queue.
The depth of the complete state graph search is <N>.
Finished in <time>.
```

### Actual TLC verification result

```text
TLC result for PhysarumMultiAgentModel
Command:           tlc PhysarumMultiAgentModel.tla -config PhysarumMultiAgentModel.cfg
Result:            Model checking completed. No error has been found.
Invariants:        TypeOK, Safety, PathSelectionSafety
SCALE:             10
States generated:  1,339,894
Distinct states:   148,877  (reachable; upper bound 11^6 = 1,771,561)
Search depth:      31
Finished in:       10s
TLC version:       TLC2 2026.05.04.141011
```

### 8.6 What the multi-agent model does NOT cover

- Reverse edges (C→B, D→C, D→B) — not needed to verify path B→D selection
- Coordinator (server A) — not an edge endpoint in the probe topology
- Concurrent scheduling, message delays, or observation windows
- The `/paths` endpoint DFS logic, MCPM, or MCTS
- The negative-log scoring formula introduced in Gate K.1 (see section 9)

---

## 9. Negative-log scoring model — `PhysarumNegativeLogModel.tla`

### 9.1 Motivation

`PhysarumMultiAgentModel.tla` uses the original product-of-conductivities path
score (`PathScoreBCD = d_ij_bc × d_ij_cd ÷ SCALE`).  Gate K.1 introduced a
negative-log scoring model that incorporates a per-extra-hop penalty, enabling
correct path re-selection in the presence of multiple healthy multi-hop paths:

```
score(p, k edges) = exp(-(Σᵢ -ln(max(q_ema_i, Q_EMA_FLOOR)) + HOP_WEIGHT × (k-1)))
                  = Πᵢ max(q_ema_i, Q_EMA_FLOOR) × exp(-HOP_WEIGHT × (k-1))
```

`PhysarumNegativeLogModel.tla` formally verifies two structural properties of
this formula that the product model cannot express.

### 9.2 Scoring formula — scaled integer representation

| Quantity | Runtime value | Scaled (SCALE=10) |
|---|---|---|
| `Q_EMA_FLOOR` | 0.001 | `Q_FLOOR = 1` |
| `exp(-HOP_WEIGHT)` | exp(-0.05) ≈ 0.9512 | `HOP_FACTOR = 9` |
| `ScoreBD` | `max(q_ema_bd, 0.001)` | `QFloor(q_ema_bd)` |
| `ScoreBCD` | `max(q_bc,0.001) × max(q_cd,0.001) × 0.9512` | `(QFloor(q_bc) × QFloor(q_cd) × 9) ÷ 10 ÷ 10` |

At SCALE=10 with all edges healthy (q_ema = SCALE):

```
ScoreBD  = 10
ScoreBCD = 10 × 10 × 9 ÷ 10 ÷ 10 = 9
```

The hop penalty correctly reduces the two-hop score below the one-hop maximum.

### 9.3 State variables and edge update

Same six variables as `PhysarumMultiAgentModel` (`q_ema_bc`, `d_ij_bc`,
`q_ema_cd`, `d_ij_cd`, `q_ema_bd`, `d_ij_bd`).  The `NextEdge` operator and
transition structure are identical — the new contribution is the scoring
operators (`ScoreBD`, `ScoreBCD`) and the two new invariants.

### 9.4 Invariants

| Invariant | Property |
|---|---|
| `TypeOK` | All 6 variables ∈ 0..SCALE |
| `Safety` | All 6 variables bounded in [0, SCALE] |
| `HopPenaltyBounds` | When all edges are at maximum conductivity, direct one-hop path outscores two-hop indirect path |
| `CrossoverCorrectness` | When indirect path wins with both indirect edges fully healthy, direct edge has degraded below `HOP_FACTOR` |

**`HopPenaltyBounds`** — formalises that `HOP_WEIGHT > 0` strictly penalises
multi-hop paths relative to an equally healthy direct path:

```
(q_ema_bc = SCALE ∧ q_ema_cd = SCALE ∧ q_ema_bd = SCALE) ⇒ ScoreBD ≥ ScoreBCD
```

At SCALE=10: ScoreBD=10 ≥ ScoreBCD=9 ✓

**`CrossoverCorrectness`** — formalises the Gate K.1 Phase 2 observation:
path re-selection to the indirect path only occurs when the direct edge has
degraded below the hop-penalty threshold.

```
(q_ema_bc = SCALE ∧ q_ema_cd = SCALE ∧ ScoreBCD > ScoreBD) ⇒ q_ema_bd < HOP_FACTOR
```

At SCALE=10: indirect wins (ScoreBCD=9 > ScoreBD) only when q_ema_bd < 9 = HOP_FACTOR.
Runtime equivalent: path flip occurs when q_ema_bd drops below ~0.91 (the crossover
threshold observed in Gate K.1 Phase 2 at q_ema_bd ≈ 0.85).

### 9.5 How to run

```bash
cd formal/tla
java -XX:+UseParallelGC -jar tla2tools.jar \
  PhysarumNegativeLogModel.tla \
  -config PhysarumNegativeLogModel.cfg
```

### 9.6 Actual TLC verification result

```text
TLC result for PhysarumNegativeLogModel
Command:           java -XX:+UseParallelGC -jar tla2tools.jar PhysarumNegativeLogModel.tla -config PhysarumNegativeLogModel.cfg
Result:            Model checking completed. No error has been found.
Invariants:        TypeOK, Safety, HopPenaltyBounds, CrossoverCorrectness
SCALE:             10  (Q_FLOOR=1, HOP_FACTOR=9)
States generated:  1,339,894
Distinct states:   148,877  (upper bound 11^6 = 1,771,561)
Search depth:      31
Finished in:       09s
TLC version:       TLC2 2026.05.04.141011
```

### 9.7 What this model does NOT cover

- Product-of-conductivities scoring (covered by `PhysarumMultiAgentModel.tla`)
- Paths with more than 2 hops (the Gate K.1 topology used B→D vs B→C→D→E;
  the 3-hop invariant is equivalent by induction on hop count but not verified here)
- physarum-maze multiplier scoring (×1.5/×0.05/×0.8/×1.2) — different model family
- Concurrent agent scheduling or observation windows

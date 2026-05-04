# TLA+ Formal Model — Adaptive Edge Dynamics

This directory contains the first formal specification for `physarum-attack-paths`.

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

## 7. Why this is not yet a full distributed-system specification

This model covers **one edge, one update step at a time**.  A full
distributed model would also need to represent:

- multiple agents running concurrently with message-passing delays;
- the coordinator's graph state and probe scheduling;
- observation windows (the 20-sample `VecDeque` per peer in each agent);
- the `/paths` and path-density endpoints planned for a future phase;
- MCPM-inspired stochastic traversal logic.

Those extensions are planned in subsequent phases of the project (see
`General-Docs/INSIGHTS_AND_BRAINSTORM.md`).  The current model isolates
the adaptive edge dynamics so they can be verified and kept stable as the
system grows.

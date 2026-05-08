# Insights and Brainstorm

This document captures exploratory ideas, research insights, and future directions for `physarum-attack-paths`.

It is intentionally separate from the operational prototype roadmap. The roadmap defines what we are building next. This document preserves promising ideas that may influence future architecture, research positioning, or patent-style invention framing.

---

## 1. MCPM-inspired attack-path density

### Source of the insight

A media article described how a slime-mold-inspired algorithm helped astronomers map dark matter and the large-scale cosmic web.

The algorithm behind that work is known as:

```text
Monte Carlo Physarum Machine — MCPM
```

Relevant research/software references for future review:

```text
- Revealing the Dark Threads of the Cosmic Web — Astrophysical Journal Letters, 2020
- Monte Carlo Physarum Machine: Characteristics of Pattern Formation in Continuous Stochastic Transport Networks — Artificial Life, 2022
- Polyphorm — MCPM-based interactive software for cosmological datasets
- PolyPhy — newer Python/open-source MCPM-style tooling for transport-network simulation
```

The important idea is not the astronomy domain itself. The important idea is the method: sparse input points can be transformed into an emergent transport-like network through many stochastic agents and accumulated path density.

---

## 2. Why MCPM is relevant to this project

The current project is already moving in a compatible direction.

Current implemented direction:

```text
local observation window -> enriched ProbeReport -> Q_ij -> q_ema -> D_ij
```

Current architectural interpretation:

```text
real agents = local sensory organs
ProbeReport = stimulus
q_ema = smoothed stimulus memory
D_ij = adaptive edge conductivity
server graph = long-term morphology
```

MCPM suggests a future extension:

```text
simulated agents traverse the adaptive graph
simulated traversal deposits trace density
frequent traversal reinforces likely attack conduits
low-density paths remain weak or decay
path density becomes an additional risk signal
```

This is conceptually powerful because attack-path analysis should not only compute a single best path. Real environments often contain multiple plausible paths, weak secondary paths, partial paths, and emergent routes that become important only when combined.

---

## 3. Difference between MCPM and the current implementation

### MCPM

```text
Input: sparse points in 2D/3D space
Method: many stochastic simulated particles/agents explore the domain
Signal: accumulated trajectory density
Output: continuous filament-like transport network
Example use: cosmic web / dark matter / gas filament inference
```

### Current physarum-attack-paths prototype

```text
Input: real agents, peer probes, local observations, future vulnerability metadata
Method: distributed reports plus adaptive graph update
Signal: Q_ij, q_ema, D_ij
Output: explicit directed adaptive graph
Example use: cyber attack-path inference and prioritization
```

The current system is graph-oriented and evidence-driven. MCPM is field/density-oriented and simulation-driven.

A future design could combine both:

```text
real agents provide evidence
server builds adaptive graph morphology
simulated agents explore that graph
path-density estimates emerge from repeated stochastic traversal
```

---

## 4. Future architecture idea

Possible future component:

```text
MCPM-inspired Path Exploration Engine
```

Potential responsibility:

```text
Run simulated agents over the adaptive attack graph.
Choose next hops probabilistically based on D_ij, q_ema, vulnerability pressure, asset criticality, and layer-transition cost.
Deposit traversal traces on edges and paths.
Aggregate path density over time.
Expose top attack conduits by density, not only shortest path.
```

Possible future signal fields:

```text
edge_trace_density
path_trace_density
path_visit_count
path_decay_rate
dominant_conduits
secondary_conduits
emergent_weak_paths
```

Possible future endpoint:

```text
GET /paths
GET /path-density
GET /conduits
```

This should remain future work. It should not be implemented before the base A/B/C and A/B/C/D labs are stable.

---

## 5. Potential mapping to cyber attack paths

MCPM cosmic-web mapping:

```text
galaxies = attractor points
agent trajectories = inferred filaments
trajectory density = probable cosmic structure
```

Possible cyber mapping:

```text
assets/services/vulnerabilities = attractor points
adaptive graph edges = possible movement channels
simulated traversal = possible attacker movement
trace density = probable attack-path conduit
```

Current graph fields that could feed future traversal:

```text
D_ij
q_ema
success_rate
avg_rtt_ms
jitter_ms
sample_count
last_seen
```

Future graph fields that may improve traversal:

```text
asset_criticality
vulnerability_pressure
known_exploited_vulnerability_flag
EPSS
CVSS
service_exposure_score
onion_layer
layer_transition_cost
credential_or_trust_signal
```

---

## 6. Key insight for future invention framing

A strong framing for the project:

> The system does not merely compute a shortest attack path. It continuously remodels an adaptive attack-path morphology from distributed local stimuli, and may further use stochastic path-density exploration to reveal dominant and secondary attack conduits.

This helps distinguish the project from traditional approaches:

```text
traditional scanner -> finding -> severity -> ticket
traditional graph tool -> static graph -> shortest path
this project -> distributed sensing -> adaptive morphology -> multi-path density and living graph memory
```

---

## 7. Manager recommendation

Do not implement MCPM-inspired path exploration immediately.

Recommended order:

```text
1. Keep validating A/B/C with q_ema and enriched ProbeReport.
2. Add A/B/C/D lab with a fourth agent representing a deeper or crown-jewel layer.
3. Implement a basic /paths endpoint using existing D_ij/q_ema values.
4. Only then consider MCPM-inspired stochastic path-density exploration.
```

Reason:

```text
MCPM-inspired traversal is promising, but it depends on a stable adaptive graph first.
Without a reliable graph substrate, path-density simulation would only add complexity.
```

---

## 8. Future research task

Possible future issue title:

```text
Research: evaluate MCPM-inspired stochastic path-density exploration for adaptive attack graphs
```

Possible scope:

```text
- Review MCPM papers and available code.
- Compare continuous MCPM with graph-based stochastic traversal.
- Prototype a small offline simulation using a saved /graph snapshot.
- Evaluate whether trace density adds useful prioritization beyond D_ij and simple path scoring.
- Keep this as research only until the A/B/C/D prototype and /paths endpoint are stable.
```

---

## 9. Future Research: MCTS/Self-Play Graph Traversal for Path Prioritization

> This is not part of the core architecture. The core remains Physarum polycephalum-inspired adaptive graph formation and path scoring; MCTS/self-play is recorded only as a possible future research layer for validation prioritization.

### Source

```text
"Learning to traverse over graphs with a Monte Carlo tree search-based self-play framework"
Engineering Applications of Artificial Intelligence, 2021
https://www.sciencedirect.com/science/article/abs/pii/S0952197621002700
```

The paper proposes an OmegaZero-style framework (graph representation learning + trajectory memory + MCTS + reinforcement learning + self-play) to learn graph traversal and combinatorial optimization heuristics.

### Why it is relevant

The current prototype answers: *what paths exist and how well do they score?*

A future MCTS/self-play layer could answer: *which path or edge should an autonomous validation agent probe next?*

This is a qualitatively different capability — moving from passive scoring to active, learned prioritization.

### Mapping to this project

The paper and this project both operate over graph traversal problems, but from different starting points:

| Paper | This project |
|---|---|
| Graph = combinatorial optimization (TSP/VRP) | Graph = observed cyber reachability (live D_ij / q_ema) |
| Objective = learn an efficient traversal/search policy | Objective = discover, rank, and validate attack paths |
| Method = GAT/GRU + MCTS + RL + self-play | Method today = Physarum conductivity + adaptive path scoring |
| Output = optimized tour/route | Output today = ranked paths via `/paths` |

### Proposed future component

```text
MCTS Path Prioritizer
```

Possible inputs:

```text
GraphSnapshot
EdgeSnapshot: source, target, d_ij, q_ema, sample_count
Agent metadata: layer, role, criticality, exposure, historical probe outcomes
Target objective: crown jewel / protected node / target layer
Recent validation outcomes
```

Possible outputs:

```text
next edge to validate
next path to probe
top-k candidate paths with exploration score
uncertainty-driven validation queue
```

Possible reward signals for self-play:

```text
successful probe → positive
new edge discovery → positive
path to target found → positive
increase in D_ij after validation → positive
proximity to high-value target → positive
failed or redundant validation → negative or zero
confirmation of segmentation drift → strong positive
```

### Relationship to existing `/paths`

This should not replace `/paths`. The proposed evolution is staged:

```text
Stage 1 (current):  /paths — deterministic adaptive path scoring over observed graph
Stage 2 (future):   add path features suitable for learning (visit count, uncertainty, target distance)
Stage 3 (future):   offline simulator/replay environment using saved GraphSnapshots
Stage 4 (future):   MCTS prototype for path/edge prioritization
Stage 5 (future):   optional learned policy from simulated/self-play trajectories
```

### Why not implement now

MCTS/self-play is premature until the graph and path behavior are proven under at least two AWS topologies:

```text
Phase 1 — full mesh (validated, PR #43)
Phase 2 — segmented B→C→D (pending runtime validation, Issue #47)
```

After Phase 2 confirms that removing B↔D edges causes edge decay and forces `/paths` to reroute via C, the graph substrate is proven stable enough to serve as the ground truth environment for a learned traversal policy.

### Out of scope until prerequisites are met

```text
new crate
new endpoint
RL model training
MCTS runtime engine
Graph neural network (GAT/GRU)
Python ML pipeline
GPU training
```

This note is research positioning only.


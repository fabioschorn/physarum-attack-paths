# Insights and Brainstorm

This document captures exploratory ideas, research insights, and future directions for `physarum-attack-paths`.

It is intentionally separate from the operational prototype roadmap. The roadmap defines what we are building next. This document preserves promising ideas that may influence future architecture, research positioning, or patent-style invention framing.

**Last reviewed:** 2026-05-24 — sections annotated with current status after Gates K.1, L, M, M.4, PF-1, PF-2.

---

## 1. MCPM-inspired attack-path density

> **Status (2026-05-24):** All prerequisites now met (stable `/paths`, Gate K.1, autonomous propagation). MCPM remains future work — deferred until `physarum-llm` (Issue #106) is validated. See section 7 for updated ordering.

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

> **Status (2026-05-24):** Steps 1–3 are complete. The project took a different direction for step 4 — autonomous propagation (physarum-maze, PF-1, PF-2) and LLM-aware adaptive propagation (physarum-llm, Issue #106) were prioritised over MCPM. MCPM remains valid as the next research layer after physarum-llm is validated.

Original order (recorded for historical reference):

```text
1. Keep validating A/B/C with q_ema and enriched ProbeReport.        ✔ DONE — Gates A–H
2. Add A/B/C/D lab with a fourth agent.                              ✔ DONE — Gate K.1 (5-node)
3. Implement a basic /paths endpoint using existing D_ij/q_ema.      ✔ DONE — Gate K.1 negative-log scoring
4. Only then consider MCPM-inspired stochastic path-density.         → DEFERRED — after physarum-llm (Issue #106)
```

Updated order (current):

```text
4a. physarum-llm — LLM-aware adaptive propagation (Issue #106)       → IN PLANNING
4b. MCPM-inspired path density — after 4a is validated               → FUTURE
```

Reason for revised order:

```text
The Causal Continuity Paradox (see Issue #106) is a more fundamental gap than path
density. An organism that cannot cross a port-80-only host gains nothing from MCPM
until it can propagate across any accessible port. physarum-llm resolves that first.
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

> **Status (2026-05-24):** Prerequisites now met — Phase 1 (full mesh) and Phase 2 (segmented B→C→D) both validated. The "active, learned prioritization" role is currently being filled by `physarum-llm` (Issue #106), which uses an LLM oracle instead of RL. MCTS/self-play remains a valid long-term research direction and may complement physarum-llm once the LLM integration is stable. The `PropagationStrategy` output from physarum-llm (confidence score, method, rationale) is a natural precursor to the reward signals described below.

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

---

## 10. Micromouse-inspired exploration and RustScan candidate-path discovery

> **Status (2026-05-24):** The Micromouse framing predicted the gate sequence K→L→M→N. Gates K, K.1, L, L.2, L.3, M, M.4 are complete. PF-1 and PF-2 labs validated autonomous propagation beyond the original scope of Gate M (full SCP+SSH self-propagation with lineage, stimulus-driven scoring, secondary conduits). Gate N (mTLS) is next. The framing remains valid as a communication tool; the sensing model (RustScan + active probes + eBPF) is implemented in `physarum-maze`.

### Source of the insight

Micromouse is a competitive robotics discipline in which an autonomous robot enters an unknown maze, explores it, builds an internal map, and then runs the fastest possible route to the centre.

The key insight is the two-phase structure:

```text
Phase 1 — exploration: the robot moves through unknown corridors, senses walls, and updates its maze map.
Phase 2 — optimized run: the robot uses the completed map to run the fastest (not necessarily shortest) route.
```

The fastest path is not always the shortest path. A longer corridor with better turning radius can be faster than a shorter one with many tight turns.

### Mapping to physarum-attack-paths

| Micromouse concept | physarum-attack-paths equivalent |
|---|---|
| Unknown maze | Unknown network / lab topology |
| Walls / corridors | Blocked / reachable network channels |
| IR sensors | RustScan + active probes + eBPF passive observation |
| Maze memory (internal map) | Adaptive graph (GraphSnapshot, EdgeSnapshot) |
| Flood fill / route planning | Path scoring and reinforcement model (`/paths`) |
| Fastest path, not shortest | Best path by latency, loss, jitter, stability, and flow evidence |
| Single robot body | Distributed agent organism |

The key difference:

```text
Micromouse: one robot traverses a static maze.
Physarum-attack-paths: a distributed agent organism occupies, senses, reinforces, and adapts through network paths. The maze is live and can change.
```

---

### Sensing model

Micromouse uses IR sensors to detect walls one step ahead. This project uses three complementary sensing mechanisms:

```text
RustScan (future)  -> candidate-path discovery: find open ports and services on adjacent hosts
active probes      -> viability testing: confirm reachability and measure quality (latency, loss, jitter)
eBPF observer      -> passive-flow confirmation: observe real OS-level TCP flows without adding probe traffic
```

RustScan provides candidate-path discovery. It helps the organism identify possible next channels when no peer list is pre-declared — analogous to the Micromouse detecting a new open corridor.

Active probes correspond to the robot physically moving into a corridor and measuring how easy it is to traverse.

eBPF flow observation corresponds to the robot sensing traffic already flowing through a channel — confirming that the corridor is in active use, not just structurally open.

---

### Adaptive memory

Micromouse builds a complete maze map before the optimized run. This project builds an adaptive graph that is continuously updated as probes report back:

```text
Q_ij          -> raw probe quality signal
q_ema         -> smoothed quality memory (exponential moving average)
D_ij          -> adaptive edge conductivity (reinforces strong channels, weakens poor ones)
FlowObservation -> confirms that a channel carries real traffic, not only probe traffic
```

The graph is not a static map. Like a living slime mold, it continuously remodels itself based on incoming stimuli.

---

### Gate sequence — original prediction vs. actual outcome

The Micromouse analogy predicted the gate sequence. Actual outcomes annotated:

```text
Gate K    segmented adaptive flow-path lab                        ✔ DONE (Issue #76)
Gate K.1  autonomous path selection, negative-log scoring         ✔ DONE (Issue #80 / PR #82)
Gate L    RustScan-backed candidate-path discovery                ✔ DONE (physarum-scanner crate)
Gate L.2  local interface stimulus evidence                       ✔ DONE
Gate L.3  ICMP stimulus evidence                                  ✔ DONE
Gate M    controlled expansion from discovered candidates         ✔ DONE (physarum-maze, SCP+SSH propagation)
Gate M.4  scoring adapter / edge weighting                        ✔ DONE
PF-1      organic expansion maze lab (7-node AWS)                 ✔ DONE
PF-2      adaptive re-routing lab (9-node AWS, TCP/ICMP stimuli)  ✔ DONE
Gate N    mTLS + Ed25519 lineage signatures                       → PLANNED
```

Gate M went further than originally scoped: physarum-maze achieved full SCP+SSH
self-propagation with lineage recording, stimulus-driven scoring, and secondary
conduit detection — validated in real AWS labs (PF-1, PF-2).

---

### Why this framing matters

Micromouse provides a concrete and intuitive reference for explaining the project to outside audiences:

```text
"The system explores an unknown network the way a Micromouse explores an unknown maze.
It senses channels, builds a map, reinforces productive routes, and adapts when the environment changes.
Unlike a Micromouse, this system is distributed — it is an organism, not a single robot."
```

This framing is useful for research positioning, patent-style invention framing, and stakeholder communication.

### Relationship to other brainstorm sections

```text
Section 1–4  -> MCPM-inspired path density (simulation layer on top of the adaptive graph)
Section 9    -> MCTS/self-play traversal (learned prioritization layer)
Section 10   -> Micromouse-inspired exploration (sensing model and gate sequence framing)
```

These are complementary, not competing. The Micromouse framing explains sensing and exploration. MCPM explains density emergence. MCTS explains learned prioritization. All three layers depend on the adaptive graph substrate being stable first.

---

## 11. Future agent autonomy: from local reactions to strategic organism behavior

> **Status (2026-05-24):** The strategic autonomy questions listed in this section are now the formal motivation for `physarum-llm` (Issue #106 — "Causal Continuity Paradox of Origin and Destination"). The LLM oracle answers "which propagation method should I use for this target?" — the first concrete implementation of distributed strategic decision-making. See Issue #106 for the full architecture.

### Current state

The current agent (`physarum-maze`) has moved well beyond a fixed client role. It already performs bounded local autonomy:

```text
observe eBPF flow cues
filter by configured discovery scope
apply cooldown/deduplication
run exact-host discovery
promote discovered candidates to active probe targets
report validated evidence back to the graph
```

This is an important transition:

```text
old model: receive a peer list -> probe peers -> report results
current model: sense -> discover candidates -> validate -> report graph evidence
```

However, this is still local operational autonomy. The agent is not yet making global strategic decisions by itself.

---

### Strategic questions for future agents

The future role-fluid organism should eventually let agents ask and answer higher-level strategic questions such as:

```text
Which global path should I prefer?
Should I change my role from client to server?
Should I become a local coordinator?
Should I propagate state to another node?
Should I choose among multiple competing paths by myself?
Should I abandon a weak region and reinforce another?
Should I initiate secure mesh communication with another peer?
```

These questions mark the difference between:

```text
an agent that reacts locally
```

and:

```text
an organism node that participates in distributed strategy
```

---

### Mapping to future capabilities

Possible future capability mapping:

```text
Prefer global path
  -> consume /paths, selected_path, secondary_conduits, path scores, graph freshness

Change role from client to server
  -> role-fluid runtime, ServeLocal, Coordinate, local control-plane promotion

Become local coordinator
  -> distributed state handoff, coordinator failover, local graph/cache ownership

Propagate state to another node
  -> mesh communication, state reconciliation, signed graph snapshots, eventual consistency

Choose among competing paths independently
  -> local path-ranking policy, threshold logic, uncertainty scoring, expected-loss reasoning

Abandon weak region and reinforce another
  -> decay/retention policy, q_ema/D_ij thresholds, secondary conduit preservation

Initiate secure mesh communication
  -> TLS/mTLS, node identity, capability-aware peer communication, trust bootstrap
```

---

### Research framing

This moves the project toward a stronger organism claim:

```text
The system is not only a coordinator that computes paths from reports.
It is a distributed organism whose nodes can sense, validate, remember, choose, and eventually change role based on environmental conditions.
```

Near-term gates continue to prove one behavior at a time:

```text
Gate L.2  ✔ local-interface scope + eBPF-triggered discovery from inbound stimuli
Gate L.3  ✔ packet-level ICMP sensing with before/after evidence
Gate M    ✔ physarum-maze self-propagating runtime (SCP+SSH, lineage, scoring)
PF-1      ✔ organic expansion maze — autonomous multi-hop colonisation
PF-2      ✔ adaptive re-routing — lateral discovery, cross-subnet stimulus, secondary conduits
physarum-llm → LLM oracle for exploit-based propagation (Issue #106) — IN PLANNING
Gate N    → mTLS + Ed25519 lineage signatures
```

The strategic autonomy questions remain the north star — `physarum-llm` is the first
concrete gate that moves the organism from "react to known SSH targets" to "reason
about any accessible port on any reachable host."

---

## 12. Future visualization idea: wasm-lab

> **Status:** Research/backlog idea only. Not part of the current implementation roadmap.

A browser-based `wasm-lab` may still be useful later as a visualization and teaching tool for the organism model.

Possible value:

```text
show q_ema / D_ij reinforcement over time
animate PF-1/PF-2 lineage expansion
visualize secondary_conduits and already-colonized behavior
replay saved GraphSnapshot or lineage JSON evidence
explain organism behavior to non-engineering audiences
```

This should remain separate from the main README status table until there is an actual implementation issue or prototype.

Potential future issue title:

```text
Research: evaluate wasm-lab visualization for PF lineage and adaptive graph replay
```

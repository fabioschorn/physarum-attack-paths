# Insights and Brainstorm

This document captures exploratory ideas, research insights, and future directions for `physarum-attack-paths`.

It is intentionally separate from the operational prototype roadmap. The roadmap defines what we are building next. This document preserves promising ideas that may influence future architecture, research positioning, or patent-style invention framing.

**Last reviewed:** 2026-05-29 — sections annotated with current status after Gates K.1, L, M, M.4, PF-1, PF-2, the `physarum-llm` Phase 1 contract work, and the sensing-profile/native-tool-refactor discussion.

---

## 1. MCPM-inspired attack-path density

> **Status (2026-05-24):** All prerequisites now met (stable `/paths`, Gate K.1, autonomous propagation). MCPM remains future work — deferred until `physarum-llm` (Issue #106) is validated.

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

The current project is compatible with that direction:

```text
local observation window -> enriched ProbeReport -> Q_ij -> q_ema -> D_ij
```

Architectural interpretation:

```text
real agents = local sensory organs
ProbeReport = stimulus
q_ema = smoothed stimulus memory
D_ij = adaptive edge conductivity
server graph = long-term morphology
```

MCPM suggests a later extension:

```text
simulated agents traverse the adaptive graph
simulated traversal deposits trace density
frequent traversal reinforces likely attack conduits
low-density paths remain weak or decay
path density becomes an additional risk signal
```

---

## 2. Difference between MCPM and the current implementation

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

## 3. Future architecture idea: MCPM-inspired path exploration

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

Possible future endpoint family:

```text
GET /paths
GET /path-density
GET /conduits
```

This remains future research work, not the current implementation track.

---

## 4. Potential mapping to cyber attack paths

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

## 5. Key insight for future invention framing

A strong framing for the project:

> The system does not merely compute a shortest attack path. It continuously remodels an adaptive attack-path morphology from distributed local stimuli, and may further use stochastic path-density exploration to reveal dominant and secondary attack conduits.

This helps distinguish the project from traditional approaches:

```text
traditional scanner -> finding -> severity -> ticket
traditional graph tool -> static graph -> shortest path
this project -> distributed sensing -> adaptive morphology -> multi-path density and living graph memory
```

---

## 6. Manager recommendation history

> **Status (2026-05-24):** Steps 1–3 are complete. The project took a different direction for step 4 — autonomous propagation (`physarum-maze`, PF-1, PF-2) and LLM-aware adaptive propagation (`physarum-llm`, Issue #106) were prioritised over MCPM. MCPM remains valid as the next research layer after `physarum-llm` is validated.

Original order, recorded for historical reference:

```text
1. Keep validating A/B/C with q_ema and enriched ProbeReport.        ✔ DONE — Gates A–H
2. Add A/B/C/D lab with a fourth agent.                              ✔ DONE — Gate K.1
3. Implement a basic /paths endpoint using existing D_ij/q_ema.      ✔ DONE — Gate K.1 negative-log scoring
4. Only then consider MCPM-inspired stochastic path-density.         → DEFERRED — after physarum-llm
```

Updated order:

```text
4a. physarum-llm — LLM-aware adaptive propagation                   → ACTIVE DESIGN / CONTRACTS
4b. MCPM-inspired path density                                      → FUTURE
```

Reason:

```text
The Causal Continuity Paradox is a more fundamental gap than path density.
An organism that cannot cross a port-80-only host gains nothing from MCPM until it can reason about propagation across any accessible port.
```

---

## 7. Future research task: MCPM-inspired stochastic traversal

Possible future research scope:

```text
- Review MCPM papers and available code.
- Compare continuous MCPM with graph-based stochastic traversal.
- Prototype a small offline simulation using a saved /graph snapshot.
- Evaluate whether trace density adds useful prioritization beyond D_ij and simple path scoring.
```

This remains research-only until the LLM-aware propagation model is stable.

---

## 8. Future Research: MCTS/Self-Play Graph Traversal for Path Prioritization

> This is not part of the core architecture. The core remains Physarum polycephalum-inspired adaptive graph formation and path scoring; MCTS/self-play is recorded only as a possible future research layer for validation prioritization.

> **Status (2026-05-24):** Prerequisites now met — Phase 1 full mesh and Phase 2 segmented B→C→D both validated. The active learned-prioritization role is currently being filled by `physarum-llm`, which uses an LLM oracle instead of RL. MCTS/self-play remains a valid long-term research direction and may complement `physarum-llm` once the LLM integration is stable.

### Source

```text
"Learning to traverse over graphs with a Monte Carlo tree search-based self-play framework"
Engineering Applications of Artificial Intelligence, 2021
https://www.sciencedirect.com/science/article/abs/pii/S0952197621002700
```

The paper proposes an OmegaZero-style framework (graph representation learning + trajectory memory + MCTS + reinforcement learning + self-play) to learn graph traversal and combinatorial optimization heuristics.

### Mapping to this project

| Paper | This project |
|---|---|
| Graph = combinatorial optimization (TSP/VRP) | Graph = observed cyber reachability (`D_ij` / `q_ema`) |
| Objective = learn efficient traversal/search policy | Objective = discover, rank, and validate attack paths |
| Method = GAT/GRU + MCTS + RL + self-play | Method today = Physarum conductivity + adaptive path scoring |
| Output = optimized tour/route | Output today = ranked paths via `/paths` |

Possible future component:

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

---

## 9. Micromouse-inspired exploration and physarum-scanner candidate-path discovery

> **Status (2026-05-24):** The Micromouse framing predicted the gate sequence K→L→M→N. Gates K, K.1, L, L.2, L.3, M, M.4 are complete. PF-1 and PF-2 labs validated autonomous propagation beyond the original scope of Gate M. The framing remains valid as a communication tool; the sensing model (`physarum-scanner` + active probes + eBPF/packet observation) is implemented in `physarum-maze`.

Micromouse is a competitive robotics discipline in which an autonomous robot enters an unknown maze, explores it, builds an internal map, and then runs the fastest possible route to the centre.

The key insight is the two-phase structure:

```text
Phase 1 — exploration: the robot moves through unknown corridors, senses walls, and updates its maze map.
Phase 2 — optimized run: the robot uses the completed map to run the fastest route.
```

Mapping to this project:

| Micromouse concept | physarum-attack-paths equivalent |
|---|---|
| Unknown maze | Unknown network / lab topology |
| Walls / corridors | Blocked / reachable network channels |
| IR sensors | `physarum-scanner` + active probes + eBPF/packet observation |
| Maze memory | Adaptive graph / lineage memory |
| Flood fill / route planning | Path scoring and reinforcement model (`/paths`) |
| Fastest path, not shortest | Best path by latency, loss, jitter, stability, and flow evidence |
| Single robot body | Distributed agent organism |

The key difference:

```text
Micromouse: one robot traverses a static maze.
Physarum-attack-paths: a distributed agent organism occupies, senses, reinforces, and adapts through network paths. The maze is live and can change.
```

### Sensing model

```text
physarum-scanner   -> candidate-path discovery: find reachable hosts/services in bounded scope
active probes      -> viability testing: confirm reachability and measure quality
eBPF/packet senses -> passive or stimulus-driven confirmation without relying only on scheduled probes
```

`physarum-scanner` helps the organism identify possible next channels when no peer list is pre-declared — analogous to the Micromouse detecting a new open corridor.

---

## 10. Future agent autonomy: from local reactions to strategic organism behavior

> **Status (2026-05-24):** The strategic autonomy questions listed in this section are now the formal motivation for `physarum-llm` (Issue #106 — Causal Continuity Paradox of Origin and Destination). The LLM oracle answers: which propagation method should I use for this target?

The current agent (`physarum-maze`) has moved beyond a fixed client role. It already performs bounded local autonomy:

```text
observe eBPF flow cues
filter by configured discovery scope
apply cooldown/deduplication
run exact-host discovery
promote discovered candidates to active probe targets
report validated evidence back to the graph
```

This is the transition:

```text
old model: receive a peer list -> probe peers -> report results
current model: sense -> discover candidates -> validate -> report graph evidence
```

Future role-fluid organism questions:

```text
Which global path should I prefer?
Should I change my role from client to server?
Should I become a local coordinator?
Should I propagate state to another node?
Should I choose among multiple competing paths by myself?
Should I abandon a weak region and reinforce another?
Should I initiate secure mesh communication with another peer?
```

Research framing:

```text
The system is not only a coordinator that computes paths from reports.
It is a distributed organism whose nodes can sense, validate, remember, choose, and eventually change role based on environmental conditions.
```

The strategic autonomy questions remain the north star. `physarum-llm` is the first concrete gate that moves the organism from "react to known SSH targets" to "reason about any accessible port on any reachable host."

---

## 11. Future visualization idea: wasm-lab

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

---

## 12. Sensing profiles and native Rust refactoring of external security tools

> **Status (2026-05-29):** Brainstorm / architecture insight only. Do not open issues for this yet. This section records the desired direction for richer sensing inside the organism after the `physarum-llm` contracts stabilize.

The project should avoid treating external tools as permanent subprocess dependencies. The preferred direction is to study useful behavior from mature tools and refactor the relevant concepts into native Rust components that can be incorporated into the `physarum-maze` organism, similar to how `physarum-scanner` became a native project capability.

This preserves the core identity of the project:

```text
not: wrapper around external scanners
but: distributed organism with native sensory organs
```

### Sensing profile inspiration

The following scan-style parameters are useful as operational inspiration, but should be modeled as internal `SensingProfile` / `ScanProfile` behavior rather than copied as raw CLI flags:

```text
-T4  -> faster timing / higher concurrency profile
-F   -> top-ports / fast port subset profile
-Pn  -> no host-discovery dependency; treat host as alive when stimulus, lineage, TCP, or eBPF evidence already exists
```

Possible internal profiles:

```text
LowNoise
Balanced
Fast
Deep
StimulusTargeted
NoDiscovery
```

Suggested semantics:

```text
LowNoise:
  low concurrency
  longer delay
  small scoped probe set
  suitable for cautious organism expansion

Balanced:
  default bounded discovery
  moderate concurrency
  service hints when cheap

Fast:
  -T4-inspired timing
  higher bounded concurrency
  top-port focus
  reduced timeout

Deep:
  richer banner and protocol handshake collection
  larger bounded port set
  more complete fingerprint for LLM reasoning

StimulusTargeted:
  exact /32 host captured from TCP, ICMP, eBPF, or lineage stimulus
  service/version style characterization
  richer DiscoveryQuery evidence

NoDiscovery:
  -Pn-inspired behavior
  skip ICMP/host discovery assumptions
  use when ICMP is blocked or when the host is already evidenced by TCP/eBPF/lineage
```

### Native Nuclei-inspired capability

`nuclei` should be considered as inspiration for a future native Rust evidence engine, not as a permanent subprocess dependency.

Desired direction:

```text
study useful Nuclei concepts
refactor relevant behavior into Rust
integrate the result as a native physarum-maze sensory capability
feed structured evidence into DiscoveryQuery
```

Possible native outputs:

```text
template_or_check_id
protocol
service
matched_condition_summary
severity_hint
confidence
evidence_summary
safe_request_response_metadata
```

Role in the organism:

```text
physarum-scanner discovers reachable services
native nuclei-inspired module validates known patterns and vulnerability signals
physarum-llm receives structured evidence rather than raw scanner noise
policy gate decides whether any proposed propagation strategy is allowed
```

This should be evidence-first. It should not make the LLM blindly trust a finding. It should provide structured, bounded, auditable signals.

### Native SSRFmap-inspired capability

`SSRFmap` should also be treated as inspiration for future native Rust capability design, not as a permanent external tool invocation.

Desired direction:

```text
study SSRFmap concepts
extract useful SSRF discovery and validation primitives
refactor them into Rust under project control
integrate as a lab-only organism capability when policy permits
```

Role in the organism:

```text
identify SSRF-like input surfaces
validate whether the target can reach controlled internal callbacks
produce structured callback evidence
feed results into DiscoveryQuery / LlmAttemptEvidence
allow physarum-llm to reason from real SSRF evidence
```

This capability must remain bounded:

```text
owned lab only
operator-defined CIDR only
controlled callback endpoints only
no Internet target expansion
no default execution
policy-gated before use
lineage/audit evidence required
```

### Integration principle

The long-term ideal is:

```text
physarum-maze
  -> native scanner / sensing profiles
  -> native vulnerability-pattern evidence engine
  -> native SSRF evidence engine
  -> physarum-llm reasoning
  -> policy gate
  -> controlled propagation
  -> lineage update
  -> next organism loop
```

The organism should become more sensitive before it becomes more aggressive.

Recommended posture:

```text
1. Expand sensing and fingerprint richness first.
2. Feed more precise evidence into physarum-llm.
3. Keep exploitation and propagation behind explicit policy gates.
4. Refactor external-tool ideas into native Rust components instead of building a wrapper chain.
5. Do not open implementation issues for Nuclei/SSRFmap-inspired modules until the current physarum-llm path is stable.
```

This direction strengthens the project name: `Physarum Attack Paths` becomes an organism that senses, validates, reasons, reinforces, and propagates through attack paths — not merely a scanner or a static attack-graph generator.

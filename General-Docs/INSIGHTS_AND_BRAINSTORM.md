# Insights and Brainstorm

This document captures exploratory ideas, research insights, and future directions for `physarum-attack-paths`.

It is intentionally separate from the operational prototype roadmap. The roadmap defines what we are building next. This document preserves promising ideas that may influence future architecture, research positioning, or invention framing.

**Last reviewed:** 2026-05-30 — updated after `physarum-llm` contracts/client/Docker Lab work, Issue #114 structured sensing merge, Issue #115 `physarum-sporangium` / `physarum-spore` direction, and the Online/Offline Cortex brainstorm.

---

## 1. MCPM-inspired attack-path density

> **Status (2026-05-30):** All prerequisites through PF-2 and structured sensing are met. MCPM remains future work — deferred until the `physarum-llm` + evidence loop is validated with `physarum-sporangium`.

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
Input: real agents, peer probes, local observations, structured sensing, future vulnerability-pattern evidence
Method: distributed reports plus adaptive graph update
Signal: Q_ij, q_ema, D_ij, SensingResult, future PatternFinding
Output: explicit directed adaptive graph and evidence-backed reasoning loop
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

Current and near-term evidence fields that may improve traversal:

```text
SensingResult
PatternFinding
service_guess
version_hint
severity_hint
confidence
evidence_source
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

> The system does not merely compute a shortest attack path. It continuously remodels an adaptive attack-path morphology from distributed local stimuli, structured sensing evidence, and bounded validation outcomes; it may later use stochastic path-density exploration to reveal dominant and secondary attack conduits.

This helps distinguish the project from traditional approaches:

```text
traditional scanner -> finding -> severity -> ticket
traditional graph tool -> static graph -> shortest path
this project -> distributed sensing -> adaptive morphology -> structured evidence -> living graph memory
```

---

## 6. Manager recommendation history

> **Status (2026-05-30):** Steps 1–3 are complete. The project took a different direction for step 4 — autonomous propagation (`physarum-maze`, PF-1, PF-2), LLM-aware adaptive reasoning (`physarum-llm`, Issue #106), and native sensing/evidence modules were prioritised over MCPM. MCPM remains valid as a later research layer after the evidence loop stabilizes.

Original order, recorded for historical reference:

```text
1. Keep validating A/B/C with q_ema and enriched ProbeReport.        ✔ DONE — Gates A–H
2. Add A/B/C/D lab with a fourth agent.                              ✔ DONE — Gate K.1
3. Implement a basic /paths endpoint using existing D_ij/q_ema.      ✔ DONE — Gate K.1 negative-log scoring
4. Only then consider MCPM-inspired stochastic path-density.         → DEFERRED — after evidence loop
```

Updated order:

```text
4a. physarum-llm — LLM-aware adaptive reasoning                    → ACTIVE
4b. physarum-scanner SensingProfile / SensingResult                ✔ DONE — Issue #114
4c. physarum-sporangium / physarum-spore evidence engine           → ACTIVE — Issue #115
4d. MCPM-inspired path density                                     → FUTURE
```

Reason:

```text
The Causal Continuity Paradox is a more fundamental gap than path density.
An organism that can sense a port-80-only host needs structured evidence and a policy-gated reasoning loop before path-density research can add value.
```

---

## 7. Future research task: MCPM-inspired stochastic traversal

Possible future research scope:

```text
- Review MCPM papers and available code.
- Compare continuous MCPM with graph-based stochastic traversal.
- Prototype a small offline simulation using a saved /graph snapshot.
- Evaluate whether trace density adds useful prioritization beyond D_ij, SensingResult, PatternFinding, and simple path scoring.
```

This remains research-only until the LLM/evidence loop is stable.

---

## 8. Future Research: MCTS/Self-Play Graph Traversal for Path Prioritization

> This is not part of the core architecture. The core remains Physarum polycephalum-inspired adaptive graph formation and path scoring; MCTS/self-play is recorded only as a possible future research layer for validation prioritization.

> **Status (2026-05-30):** Prerequisites through PF-2 and structured sensing are now met. The active learned-prioritization role is currently being filled by `physarum-llm`, which uses an LLM oracle instead of RL. MCTS/self-play remains a valid long-term research direction and may complement the evidence loop once stable.

### Source

```text
"Learning to traverse over graphs with a Monte Carlo tree search-based self-play framework"
Engineering Applications of Artificial Intelligence, 2021
https://www.sciencedirect.com/science/article/abs/pii/S0952197621002700
```

### Mapping to this project

| Paper | This project |
|---|---|
| Graph = combinatorial optimization (TSP/VRP) | Graph = observed cyber reachability (`D_ij` / `q_ema`) |
| Objective = learn efficient traversal/search policy | Objective = discover, rank, and validate attack paths |
| Method = GAT/GRU + MCTS + RL + self-play | Method today = Physarum conductivity + adaptive path scoring + evidence loop |
| Output = optimized tour/route | Output today = ranked paths via `/paths` and future evidence-informed choices |

Possible future component:

```text
MCTS Path Prioritizer
```

Possible inputs:

```text
GraphSnapshot
EdgeSnapshot: source, target, d_ij, q_ema, sample_count
SensingResult / PatternFinding evidence
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

> **Status (2026-05-30):** Gates K, K.1, L, L.2, L.3, M, M.4 are complete. PF-1 and PF-2 labs validated autonomous propagation beyond the original scope of Gate M. Issue #114 added structured sensing profiles and `SensingResult`, making the Micromouse analogy stronger at the sensory layer.

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
| IR sensors | `physarum-scanner` + `SensingProfile` + eBPF/packet observation |
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
physarum-scanner   -> candidate-path discovery and SensingResult evidence
active probes      -> viability testing: confirm reachability and measure quality
eBPF/packet senses -> passive or stimulus-driven confirmation without relying only on scheduled probes
```

`physarum-scanner` helps the organism identify possible next channels when no peer list is pre-declared — analogous to the Micromouse detecting a new open corridor.

---

## 10. Future agent autonomy: from local reactions to strategic organism behavior

> **Status (2026-05-30):** The strategic autonomy questions listed in this section are now implemented in early form through `physarum-llm` contracts/mock/client and the Docker Lab reasoning hook. Issue #115 is the next evidence-enrichment step before deeper #106 integration.

The current agent (`physarum-maze`) has moved beyond a fixed client role. It already performs bounded local autonomy:

```text
observe eBPF flow cues
filter by configured discovery scope
apply cooldown/deduplication
run exact-host discovery
promote discovered candidates to active probe targets
record lineage evidence
invoke lab-only reasoning when configured
```

This is the transition:

```text
old model: receive a peer list -> probe peers -> report results
current model: sense -> discover candidates -> validate -> record graph/lineage evidence
next model: sense -> enrich evidence -> reason -> policy gate -> controlled action -> lineage
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

The strategic autonomy questions remain the north star. `physarum-llm` is the first concrete gate that moves the organism from "react to known SSH targets" to "reason about structured evidence on any reachable host."

---

## 11. Online and offline cortex modes for the same agent

> **Status:** Brainstorm only. No issue should be opened yet. This section records a future behavioral model for the same `physarum-maze` agent under different environmental conditions.

The same agent should be able to behave differently depending on what it senses about its environment. This is not a separate agent type; it is an internal mode switch.

Conceptually:

```text
if LLM is reachable and policy allows external reasoning:
    enter Online Cortex Mode
else:
    enter Offline Cortex Capsule Mode
```

This split helps the organism handle two very different node classes:

```text
resource-rich node:
  has outbound path to an LLM gateway or relay
  can ask for richer reasoning
  can submit graph context for evaluation
  can receive policy-constrained plan proposals

resource-poor / isolated node:
  has no Internet or no LLM route
  may only have local network visibility
  can still sense, record, score, and synchronize later
  should not escalate autonomy only because external reasoning is unavailable
```

### Online Cortex Mode — LLM reachable

Online Cortex Mode is used when the agent can reach a configured LLM endpoint directly or through an approved relay.

Input to the LLM should be structured and bounded:

```text
SensingResult[]
PatternFinding[]
FlowObservation[]
RecentLineage
GraphSnapshot or GraphDelta summary
AllowedLabScope
PolicyConstraints
KnownDeadEnds
KnownSecondaryConduits
```

The LLM should not receive uncontrolled raw dumps. It should receive evidence summaries that are already filtered, capped, and policy-aware.

Expected flow:

```text
sense
  -> enrich evidence
  -> update local graph delta
  -> prepare GraphContext
  -> call physarum-llm
  -> receive PlanProposal
  -> PolicyGate validation
  -> controlled lab action only if accepted
  -> append LineageEvent
  -> sync graph/ledger deltas
```

In this mode, the LLM is a cortex-like advisor, not the permanent memory of the organism. The durable memory should still live in graph, lineage, and policy state.

```text
LLM = reasoning advisor
Graph = memory
Lineage = history
Policy = boundary
DNA = continuity identity
```

### Offline Cortex Capsule Mode — LLM not reachable

Offline Cortex Capsule Mode is used when the agent cannot reach the LLM, cannot reach a relay, or is running on a node with limited resources or restricted egress.

The agent should not stop. It should reduce autonomy and preserve continuity.

Expected behavior:

```text
sense
  -> enrich evidence locally
  -> update local graph delta
  -> apply offline heuristic scorer
  -> append LineageEvent
  -> try parent/peer/relay sync
  -> wait for reconnection or operator-controlled export
```

The offline capsule can contain:

```text
policy snapshot
allowed scope
trusted roots
last known graph root
last known lineage root
small scoring heuristic
template/check allowlist
capability manifest
parent/relay hints
```

This mode should be conservative:

```text
observe and record: yes
enrich evidence locally: yes
update local graph delta: yes
sync with trusted peers if available: yes
perform high-risk autonomous action without current policy/LLM: no
expand scope beyond DNA/policy: no
```

### The if/else as organism behavior

A future implementation could make the mode explicit inside the agent runtime:

```text
fn choose_cortex_mode(agent_context): CortexMode {
    if llm_endpoint_reachable()
       && policy.allows_external_reasoning()
       && node_resources_are_sufficient() {
        CortexMode::Online
    } else {
        CortexMode::OfflineCapsule
    }
}
```

The important point is that both branches belong to the same organism.

```text
Online mode thinks with help.
Offline mode remembers and survives.
```

### DNA, graph, and ledger relationship

The DNA idea should not be a heavyweight public blockchain. A better fit is a lightweight internal continuity ledger:

```text
Agent DNA:
  organism_id
  agent_id
  parent_agent_id
  generation
  policy_version
  capability_manifest
  trusted_roots
  last_graph_root
  last_lineage_root

Lineage Ledger:
  append-only signed events
  parent event hash
  evidence hash
  graph delta hash
  policy version
  action/result summary

Graph Memory:
  mergeable node/edge/service observations
  dead ends
  secondary conduits
  confidence
  conductivity
  path-density candidates
```

This gives the organism continuity without requiring a central always-online brain.

### Future naming ideas

Potential component names for later consideration:

```text
physarum-dna       -> continuity identity and inherited policy roots
physarum-ledger    -> signed append-only lineage event log
physarum-graph     -> mergeable graph memory
physarum-synapse   -> peer/relay synchronization between agents
physarum-cortex    -> online/offline reasoning interface
physarum-nucleus   -> trust roots, policy, and identity boundary
```

### Design principle

```text
The agent should not become useless without Internet.
It should become more conservative.
```

And:

```text
The LLM may disappear.
The organism memory must not.
```

This section should remain in `INSIGHTS_AND_BRAINSTORM.md` until the release and current evidence loop are stable. No issues should be opened yet.

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

---

## 13. Sensing profiles and native Rust refactoring of external security tools

> **Status (2026-05-30):** Partly implemented and partly active. Issue #114 delivered `SensingProfile` and `SensingResult` in `physarum-scanner`. Issue #115 is now active for the native Nuclei-inspired Rust port, named `physarum-sporangium`; `physarum-spore` is the corresponding CLI binary. SSRFmap-inspired work remains future/backlog.

The project should avoid treating external tools as permanent subprocess dependencies. The preferred direction is to study useful behavior from mature tools and refactor the relevant concepts into native Rust components that can be incorporated into the `physarum-maze` organism, similar to how `physarum-scanner` became a native project capability.

This preserves the core identity of the project:

```text
not: wrapper around external scanners
but: distributed organism with native sensory organs
```

### Sensing profile implementation

Issue #114 implemented the internal sensing profile layer.

```text
LowNoise
Balanced
Fast
TopPorts
Deep
StimulusTargeted
NoDiscovery
```

The operational inspiration was translated into project-native semantics:

```text
-T4  -> Fast: speed/concurrency axis
-F   -> TopPorts: port-scope axis
-Pn  -> NoDiscovery: host-already-evidenced mode
```

`SensingResult` now gives the project a structured evidence envelope that can feed `physarum-llm` instead of passing only raw open ports.

### Native Nuclei-inspired capability — physarum-sporangium / physarum-spore

`nuclei` should be considered source material for a native Rust evidence engine, not a permanent subprocess dependency.

Working names:

```text
physarum-sporangium  -> crate / evidence engine
physarum-spore       -> CLI binary / pattern-evidence runner
```

Biological framing:

```text
A sporangium produces spores.
In this project, each template/check/finding can be treated as a controlled evidence spore released by the organism.
```

Desired direction:

```text
study Nuclei architecture
port relevant concepts into Rust
emit structured PatternFinding evidence
integrate with physarum-llm DiscoveryQuery
remove local upstream clone after native module is viable
```

Local upstream clones are analysis material only and are ignored by `.gitignore`:

```text
nuclei/
Nuclei/
projectdiscovery-nuclei/
```

Potential native outputs:

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
physarum-sporangium validates known patterns and vulnerability signals
physarum-llm receives structured evidence rather than raw scanner noise
policy gate decides whether any proposed action is allowed
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
  -> controlled action
  -> lineage update
  -> next organism loop
```

The organism should become more sensitive before it becomes more aggressive.

Recommended posture:

```text
1. Expand sensing and fingerprint richness first.                  ✔ Issue #114
2. Port vulnerability-pattern evidence into native Rust.           → Issue #115
3. Feed more precise evidence into physarum-llm.                   → Issue #106 next integration
4. Keep high-risk actions behind explicit policy gates.
5. Refactor external-tool ideas into native Rust components instead of building a wrapper chain.
```

This direction strengthens the project name: `Physarum Attack Paths` becomes an organism that senses, validates, reasons, reinforces, and propagates through attack paths — not merely a scanner or a static attack-graph generator.

# Insights and Brainstorm

This document captures exploratory ideas, research insights, and future directions for `physarum-attack-paths`.

It is intentionally separate from the operational prototype roadmap. The roadmap defines what we are building next. This document preserves promising ideas that may influence future architecture, research positioning, or invention framing.

**Last reviewed:** 2026-06-09 — updated with the `pentest-active` / `analysis-only` execution-mode distinction and the June 2026 adaptive self-replicating AI worm research comparison.

---

## 1. MCPM-inspired attack-path density

> **Status:** Future research. MCPM remains deferred until the LLM/evidence/lineage loop is stable.

A media article described how a slime-mold-inspired algorithm helped astronomers map dark matter and the large-scale cosmic web. The algorithm behind that work is known as:

```text
Monte Carlo Physarum Machine — MCPM
```

The important idea is not the astronomy domain itself. The important idea is the method: sparse input points can be transformed into an emergent transport-like network through many stochastic agents and accumulated path density.

The current project is compatible with that direction:

```text
local observation window -> enriched evidence -> Q_ij -> q_ema -> D_ij
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
```

### Current physarum-attack-paths prototype

```text
Input: real agents, peer probes, local observations, structured sensing, PatternFinding evidence, vulnerability candidates, and lineage
Method: distributed reports plus adaptive graph update and policy-gated reasoning
Signal: Q_ij, q_ema, D_ij, SensingResult, PatternFindingSummary, VulnerabilityCandidate, LlmAttemptEvidence
Output: explicit directed adaptive graph and evidence-backed organism loop
```

The current system is graph-oriented and evidence-driven. MCPM is field/density-oriented and simulation-driven. A future design could combine both:

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

> The system does not merely compute a shortest attack path. It continuously remodels an adaptive attack-path morphology from distributed local stimuli, structured sensing evidence, bounded validation outcomes, LLM proposals, PolicyGate decisions, and lineage memory; it may later use stochastic path-density exploration to reveal dominant and secondary attack conduits.

This helps distinguish the project from traditional approaches:

```text
traditional scanner -> finding -> severity -> ticket
traditional graph tool -> static graph -> shortest path
this project -> distributed sensing -> adaptive morphology -> structured evidence -> living graph memory
```

---

## 6. Manager recommendation history

The project took a different direction after the early graph gates: autonomous propagation (`physarum-maze`), LLM-aware adaptive reasoning (`physarum-llm`), structured sensing (`physarum-scanner`), and the Nuclei-compatible evidence engine (`physarum-sporangium`) were prioritized over MCPM.

MCPM remains valid as a later research layer after the current evidence loop stabilizes.

Original order, retained for historical reference:

```text
1. Keep validating A/B/C with q_ema and enriched ProbeReport.        ✔ DONE — Gates A–H
2. Add A/B/C/D lab with a fourth agent.                              ✔ DONE — Gate K.1
3. Implement a basic /paths endpoint using existing D_ij/q_ema.      ✔ DONE — Gate K.1 negative-log scoring
4. Only then consider MCPM-inspired stochastic path-density.         → DEFERRED — after evidence loop
```

Updated order:

```text
4a. physarum-llm — LLM-aware adaptive reasoning                    ✔ IMPLEMENTED
4b. physarum-scanner SensingProfile / SensingResult                ✔ DONE
4c. physarum-sporangium / physarum-spore evidence engine           ✔ ACTIVE CORE CAPABILITY
4d. PF-6 Phase 2 ephemeral-key SCP propagation                     → ACTIVE — Issue #141
4e. MCPM-inspired path density                                     → FUTURE
```

---

## 7. Future research task: MCPM-inspired stochastic traversal

Possible future research scope:

```text
- Review MCPM papers and available code.
- Compare continuous MCPM with graph-based stochastic traversal.
- Prototype a small offline simulation using a saved graph snapshot.
- Evaluate whether trace density adds useful prioritization beyond D_ij, SensingResult, PatternFinding, and path scoring.
```

This remains research-only until the LLM/evidence loop is stable.

---

## 8. Future Research: MCTS/Self-Play Graph Traversal for Path Prioritization

> This is not part of the core architecture. The core remains Physarum polycephalum-inspired adaptive graph formation and path scoring. MCTS/self-play is recorded only as a possible future research layer for validation prioritization.

Possible future component:

```text
MCTS Path Prioritizer
```

Possible inputs:

```text
GraphSnapshot
EdgeSnapshot: source, target, D_ij, q_ema, sample_count
SensingResult / PatternFinding evidence
VulnerabilityCandidate evidence
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
| Flood fill / route planning | Path scoring and reinforcement model |
| Fastest path, not shortest | Best path by evidence, reliability, stability, and policy outcome |
| Single robot body | Distributed agent organism |

The key difference:

```text
Micromouse: one robot traverses a static maze.
Physarum-attack-paths: a distributed agent organism occupies, senses, reinforces, and adapts through network paths. The maze is live and can change.
```

---

## 10. Future agent autonomy: from local reactions to strategic organism behavior

The current agent (`physarum-maze`) has moved beyond a fixed client role. It already performs bounded local autonomy:

```text
observe eBPF flow cues
filter by configured discovery scope
apply cooldown/deduplication
run startup or stimulus-targeted discovery
promote discovered candidates to active probe targets
record lineage evidence
invoke lab-only reasoning when configured
```

This is the transition:

```text
old model: receive a peer list -> probe peers -> report results
current model: sense -> discover candidates -> validate -> enrich -> reason -> policy gate -> controlled action -> lineage
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

Online Cortex Mode is used when the agent can reach a configured LLM endpoint directly or through an approved relay. The LLM receives structured, bounded evidence summaries, not uncontrolled raw dumps.

Offline Cortex Capsule Mode is used when the agent cannot reach the LLM, cannot reach a relay, or is running on a node with limited resources or restricted egress. The agent should not stop; it should become more conservative.

Expected offline behavior:

```text
sense
  -> enrich evidence locally
  -> update local graph delta
  -> apply offline heuristic scorer
  -> append LineageEvent
  -> try parent/peer/relay sync
  -> wait for reconnection or operator-controlled export
```

Design principle:

```text
The agent should not become useless without Internet.
It should become more conservative.
```

And:

```text
The LLM may disappear.
The organism memory must not.
```

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

## 13. Sensing profiles, sporangium evidence, and exploit-reference enrichment

> **Status:** Brainstorm / design note. `physarum-scanner`, `physarum-sporangium`, `VulnerabilityIntelService`, and the two-turn LLM loop are active project capabilities. Exploit-reference enrichment is a future extension for PF-6 Phase 2 and later AWS-controlled labs.

The project should avoid treating external tools as permanent subprocess dependencies. The preferred direction is to study useful behavior from mature tools and refactor relevant concepts into native Rust components or tightly bounded metadata lookups that can be incorporated into the `physarum-maze` organism.

This preserves the core identity of the project:

```text
not: wrapper around external scanners
but: distributed organism with native sensory organs and bounded evidence enrichment
```

### Sensing profile implementation

`SensingResult` gives the project a structured evidence envelope that can feed `physarum-llm` instead of passing only raw open ports.

Operational scanning ideas are translated into project-native semantics:

```text
-T4  -> Fast: speed/concurrency axis
-F   -> TopPorts: port-scope axis
-Pn  -> NoDiscovery: host-already-evidenced mode
```

### Nuclei-compatible capability — physarum-sporangium / physarum-spore

`physarum-sporangium` is the native Rust evidence engine used by `physarum-maze` after sensing identifies reachable services.

Role in the organism:

```text
physarum-scanner discovers reachable services
physarum-sporangium validates known patterns and vulnerability signals
VulnerabilityIntelService enriches findings into vulnerability_candidates
physarum-llm receives structured evidence rather than raw scanner noise
PolicyGate decides whether any proposed action is allowed
```

This should remain evidence-first. It should not make the LLM blindly trust a finding. It should provide structured, bounded, auditable signals.

### Exploit-DB / SearchSploit enrichment after sporangium

After `physarum-sporangium` executes applicable templates and `VulnerabilityIntelService` generates `vulnerability_candidates`, Phase 2 should make it explicit to the LLM that Exploit-DB/SearchSploit exists as an available enrichment capability.

The enrichment should not silently pre-bake `DiscoveryQuery` before the LLM has reasoned over the observed evidence. The better ordering is:

```text
physarum-maze
  -> physarum-scanner / SensingResult
  -> LLM Turn 1 template selection
  -> physarum-sporangium template execution
  -> PatternFindingSummary
  -> VulnerabilityIntelService / vulnerability_candidates
  -> DiscoveryQuery / LLM Turn 2
       includes: available_enrichment_capabilities = [ExploitDB, SearchSploitLocal]
  -> LLM requests exploit-reference enrichment when useful
  -> physarum-maze performs Exploit-DB / SearchSploit lookup
  -> enriched DiscoveryQuery / LLM Turn 2 continuation
  -> LLM proposes bounded typed strategy
  -> PolicyGate
  -> controlled lab action
  -> lineage update
```

The LLM should receive structured exploit-reference metadata, not unrestricted exploit execution authority.

Potential metadata shape:

```text
exploit_reference_id
source = ExploitDB | SearchSploitLocal
cve_id
product
version_range
platform
exploit_type
verified_status
requires_auth
requires_user_interaction
requires_outbound_callback
expected_effect
safety_class
local_path_or_url_reference
summary
```

The expected behavior:

```text
1. physarum-sporangium produces observed evidence.
2. VulnerabilityIntelService proposes vulnerability_candidates.
3. Initial DiscoveryQuery for LLM Turn 2 includes available enrichment capability metadata.
4. LLM Turn 2 may request Exploit-DB/SearchSploit reference enrichment.
5. physarum-maze validates the request against policy/scope.
6. physarum-maze performs the lookup locally or through an approved online source.
7. physarum-maze returns structured exploit-reference metadata to the LLM as a continuation/refinement input.
8. LLM proposes a bounded strategy using typed actions only.
9. PolicyGate decides whether the proposed action is allowed.
10. Lineage records the chosen reference, enrichment request, policy decision, and outcome.
```

The enrichment must remain bounded:

```text
owned lab only
operator-defined CIDR only
no public target expansion
no automatic exploit execution
no raw exploit payload pasted into lineage by default
no private key, API key, token, or .env.local content in prompts or evidence
LLM does not execute SearchSploit directly
physarum-maze executes only bounded enrichment lookups
PolicyGate approval required before any action
lineage/audit evidence required
```

Online and offline modes should both be possible:

```text
Online mode:
  query public Exploit-DB or approved advisory sources only when Internet is explicitly allowed

Offline mode:
  use a local SearchSploit database or curated exploit-reference cache
```

The important design point: Exploit-DB/SearchSploit should help the LLM rank and explain feasible lab-only validation paths after `physarum-sporangium` has already produced observed evidence. It should not replace sensing, template execution, vulnerability intelligence, PolicyGate, or lineage.

### Integration principle

The long-term ideal is:

```text
physarum-maze
  -> native scanner / sensing profiles
  -> Nuclei-compatible vulnerability-pattern evidence engine
  -> vulnerability intelligence
  -> LLM-visible enrichment capabilities
  -> LLM-requested exploit-reference enrichment
  -> physarum-llm reasoning
  -> PolicyGate
  -> controlled lab action
  -> lineage update
  -> next organism loop
```

The organism should become more evidence-rich before it becomes more aggressive.

Recommended posture:

```text
1. Expand sensing and fingerprint richness first.                     ✔ Done
2. Execute sporangium templates and produce PatternFinding evidence.  ✔ Active core
3. Expose safe enrichment capabilities to the LLM.                    → Future/Phase 2+
4. Let physarum-maze perform bounded enrichment when requested.       → Future/Phase 2+
5. Feed structured evidence into physarum-llm.                        ✔ Active core
6. Keep high-risk actions behind explicit policy gates.               ✔ Mandatory
7. Prefer native Rust components and curated metadata over wrappers.   ✔ Direction
```

This direction strengthens the project name: `Physarum Attack Paths` becomes an organism that senses, validates, reasons, reinforces, and propagates through attack paths — not merely a scanner or a static attack-graph generator.

---

## 14. Execution modes after propagation: `pentest-active` and `analysis-only`

> **Status (2026-06-09):** Proposed architecture and manager review item. This section records the intended separation between controlled propagation/validation and post-propagation graph analysis.

The same `physarum-maze` runtime should support two explicitly different operational modes.

### `pentest-active`

This mode exists to validate attack paths and propagate the organism inside an owned, private, policy-scoped lab.

Expected flow:

```text
sense
  -> discover
  -> validate
  -> enrich evidence
  -> choose a path
  -> request policy approval
  -> execute an authorized action
  -> create or transfer functional presence to the next node
  -> append lineage
  -> update graph morphology
```

This mode may perform controlled propagation, but only under explicit scope, generation, node-count, concurrency, credential, and kill-switch constraints.

Minimum controls:

```text
owned_lab = true
scope_defined = true
policy_gate = required
lineage = required
kill_switch = required
max_generations = bounded
max_new_nodes = bounded
external_target_expansion = false
```

### `analysis-only`

This mode is intended for the period after `physarum-maze` is already distributed across approved nodes and the research objective changes from expansion to analysis of new stimuli.

Expected flow:

```text
existing agents observe new stimuli
  -> produce SensingResult / PatternFinding evidence
  -> update q_ema / D_ij
  -> recalculate competing paths
  -> identify new, degraded, or recovered conduits
  -> detect barrier-crossing risk
  -> prioritize findings for the Blue Team
```

Allowed behavior:

```text
observe local telemetry
collect bounded evidence
update confidence and conductivity
recalculate paths
compare graph changes over time
identify unintended propagation routes
emit prioritized findings
```

Blocked behavior:

```text
new exploitation
new propagation
new agent creation
scope expansion
credential-based movement
role escalation
high-risk validation actions
```

The central distinction is:

```text
pentest-active = validate and expand under policy
analysis-only  = sense, remember, recalculate, and report without further expansion
```

The execution mode should be separate from the organism lifecycle state. Example:

```yaml
organism_state: propagated
execution_mode: analysis-only
```

A mode transition should be explicit and auditable:

```text
pentest-active
  -> authorized propagation objective reached
  -> operator or manager approval
  -> analysis-only
  -> continued sensing and graph remodeling
```

The transition should generate a lineage event containing the previous mode, new mode, policy version, reason, approving authority, and current graph root.

### Research significance

This separation supports two different hypotheses:

```text
Hypothesis A — controlled propagation:
An LLM-assisted organism can establish functional presence on new approved nodes by following evidence-backed attack paths.

Hypothesis B — post-propagation morphology:
After distribution, the organism can continue sensing environmental changes and remodeling the graph without continuing to propagate.
```

Without replication or functional deployment to new nodes, the project can still build an analytical map, but it does not become a distributed organism in the strong operational sense. The propagation phase creates distributed presence; the analysis phase turns that presence into a persistent sensory and morphological memory.

### Related June 2026 research

The following research should be reviewed by the Manager as relevant state of the art:

```text
AI Agents Enable Adaptive Computer Worms
arXiv: 2606.03811
Submitted: 2026-06-02
https://arxiv.org/abs/2606.03811
```

Public coverage:

```text
Researchers Build Self-Replicating AI Worm That Operates Entirely on Local, Open-Weight Models
The Hacker News, June 2026
https://thehackernews.com/2026/06/researchers-build-self-replicating-ai.html?m=1
```

That work demonstrates a closely related capability class: a local open-weight LLM agent can perform adaptive exploitation and self-replication across an isolated vulnerable network. This reduces the novelty of a broad claim such as "LLM agent self-replication is possible," but it does not eliminate the distinct research space of `physarum-attack-paths`.

The project should therefore preserve and emphasize its differentiated contribution:

```text
adaptive Physarum-inspired graph morphology
q_ema / D_ij reinforcement and decay
competing-path re-selection
lineage-aware distributed continuity
policy-gated execution modes
post-propagation sensing and graph remodeling
identification of unintended propagation nodes
Blue Team prioritization of barrier-crossing paths
```

### Manager decision point

The recommended direction is to continue the current PF-6 development, complete controlled `pentest-active` propagation, and then add `analysis-only` as a distinct execution profile for already-propagated agents.

The Manager should assess:

```text
1. Whether execution mode belongs in agent configuration, signed policy, or both.
2. Which capabilities are disabled structurally in analysis-only mode.
3. Which lineage events prove mode transitions and propagation generations.
4. Which benchmark compares Physarum path selection with a conventional LLM-driven worm.
5. How the external paper should be cited in future research and invention-positioning documents.
```
Fábio Schorn

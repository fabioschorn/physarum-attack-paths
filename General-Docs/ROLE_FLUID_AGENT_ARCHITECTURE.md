# Role-Fluid Agent Architecture — Roadmap and Design Intent

**Status:** Historical design intent — superseded in part by Gate M/M.4, PF-1, and PF-2  
**Issue:** #63  
**Author:** Dev Lead  
**Date:** 2026-05-11

---

## Summary

This document captures the architectural direction that led from the original eBPF Stage 0 design toward the role-fluid `physarum-node` and autonomous `physarum-maze` organism model.

Several ideas in this document were originally future-looking. Many are now implemented or superseded:

```text
Gate I/J/J.1   eBPF observation and FlowObservation API validated
Gate L         physarum-scanner native discovery engine implemented
Gate M/M.4     physarum-node runtime and probe/discovery consolidation completed
PF-1/PF-2      autonomous maze propagation and adaptive re-routing validated
```

This document should be read as design history and architectural intent. The current canonical architecture is maintained in `General-Docs/ARCHITECTURE.md`.

---

## 1. Validated foundation

Gates A through H established that the core reinforcement mechanism works under real network conditions before autonomous behavior is attempted.

```text
Gate A   Design S3 artifact delivery and EC2 bootstrap
Gate B   Implement S3 delivery + IAM role + real user_data
Gate C   Validate AWS Mode 1 full mesh runtime — agent ↔ server over real EC2/VPC
Gate D   AWS Phase Identity — lab_phase variable, resource naming, SG topology
Gate E   AWS Mode 2 segmented B→C→D runtime validation
Gate F   B/C/D TLA+ Path-Selection Model — formal verification of path re-selection under degradation
Gate G   Docker Weighted Competing Paths Validation — Physarum scoring in controlled containers
Gate H   AWS tc/netem Weighted Competing Paths Validation — real network degradation and convergence
```

Gate H was the critical validation:

```text
two competing paths with real tc/netem degradation
path re-selection emerged from scoring state after network quality changed
q_ema and D_ij reinforcement/decay cycle proven under real AWS conditions
```

This foundation remains valid. The scoring mechanism does not change — the input signals and runtime capabilities generalize.

---

## 2. eBPF direction

Passive flow observation adds evidence that active probing alone cannot provide.

```text
physarum-agent           core agent: probing, scoring, reporting
physarum-ebpf-observer   sidecar: TCP state tracepoint, metadata only
```

The original two-process layout was a transitional validation design. It was useful because:

```text
eBPF complexity could be validated independently
observer restart/replacement did not disturb the stable agent
CAP_BPF / CAP_PERFMON stayed isolated in the sidecar
```

This work was later incorporated into the broader role-fluid direction through Gate M and Gate M.4.

---

## 3. Role-fluid runtime direction

The long-term direction is a unified organism runtime where one binary can carry multiple capabilities and activate them according to the environment.

```text
original transitional layout       role-fluid direction
───────────────────────────        ───────────────────────────────────────
physarum-agent                     physarum-node / physarum-maze organism
physarum-ebpf-observer                 probe execution
                                      packet/eBPF observation
                                      native discovery
                                      scoring
                                      controlled propagation
                                      lineage/state memory
```

The role-fluid idea is now partially validated:

```text
Gate M      physarum-node supervises role-specific children
Gate M.4    probe/discovery internalized through physarum-probe
PF-1/PF-2   physarum-maze validates autonomous organism behavior
```

---

## 4. Role-fluid agent model

A role-fluid agent is not permanently fixed as only a client or only a server. Its responsibilities can adapt to network state and local evidence.

### Roles an organism node may assume

```text
coordinator / server      bootstraps or exposes graph state
client / reporter         probes paths and reports scores
flow observer             observes kernel/network metadata
service-discovery worker  runs physarum-scanner discovery on candidate hosts
path scorer               computes or contributes to q_ema / D_ij scoring
expansion unit            propagates to the next highest-scored node in a lab
local recovery            preserves organism behavior when upstream path weakens
```

### Role transition example

```text
Initial state:
  machine A = seed / coordinator-like organism node

Expansion:
  A propagates to B and C in a controlled lab
  B and C continue sensing and reporting from their new positions

Role transition:
  a downstream node observes a stronger path than the original seed path
  the organism reinforces the new path and preserves old useful paths as secondary conduits
```

This matches the Physarum analogy:

```text
spread through the maze
reinforce useful channels
abandon weak / dead paths
continue growing from viable points even when the original seed point is no longer dominant
```

### Core conceptual principle

```text
Agents are not only observers of paths.
Agents are the computational substance that occupies and reinforces paths.
```

---

## 5. physarum-scanner as an organism capability

`physarum-scanner` is the native discovery engine for the project.

### Intended role

```text
eBPF or packet stimulus identifies candidate destinations worth probing.
physarum-scanner enumerates reachable services or hosts within the bounded lab scope.
Discovery results feed into the physarum graph as candidate edges and nodes.
```

### Integration model

```text
physarum-scanner is an internal project crate
not an external subprocess dependency
scan/discovery results -> candidate observations -> graph edges and organism decisions
```

### Semantic rule

```text
Open ports are exposure observations, not proof of authorized access or exploitability.
```

Discovery enriches the graph. It does not grant authorization or imply that the organism may proceed outside operator-defined scope.

---

## 6. Controlled Physarum-inspired expansion

The project models agents as computational analogues of *Physarum polycephalum*. In controlled environments, agents may use passive-flow evidence, packet-level stimulus, and native discovery to identify candidate next steps, reinforce productive paths, and decay weaker or unproductive paths.

### Autonomous propagation cycle

```text
1. Packet/eBPF observer detects stimulus from a reachable host
        -> inbound TCP/ICMP signal becomes a candidate to explore

2. physarum-scanner performs bounded discovery
        -> local /24 discovery or targeted /32 characterization depending on context

3. Physarum scoring ranks available paths
        -> strongest filament = highest scored path = preferred next movement

4. Agent propagates in the controlled lab
        -> graph expands dynamically at runtime
        -> no pre-defined final target required

5. Weak paths decay and dead ends are abandoned
        -> the organism self-organizes around reachable, productive paths
```

### How q_ema / D_ij generalizes to the autonomous model

The scoring formula does not change. The input signals generalize:

```text
eBPF / packet stimulus  -> stronger edge signal
physarum-scanner result -> reachable candidate evidence
Propagation outcome     -> successful movement reinforces the edge
Dead end                -> score decays, path becomes less preferred
New node discovered     -> candidate edge is bootstrapped and evaluated
```

---

## 7. Actual outcome vs original intent

Original intended sequence:

```text
1. eBPF passive flow observation
2. native service discovery
3. controlled Physarum-inspired expansion
```

Actual validated outcome:

```text
1. eBPF and packet observation validated through Gates I/J/J.1/L.3
2. physarum-scanner implemented and used in Gates L/L.1/L.2/PF-1/PF-2
3. physarum-node consolidated runtime roles in Gate M/M.4
4. physarum-maze validated autonomous propagation in PF-1/PF-2
```

---

## 8. What this document does NOT authorize

```text
Uncontrolled expansion
Internet scanning
Public target probing
Production deployment without Gate N security design
LLM-assisted propagation before Issue #106 design/safety review
```

---

## 9. Relationship to current documents

```text
ARCHITECTURE.md                    current canonical system architecture
QUALITY_GATE.md                    current gate status and acceptance criteria
EBPF_FLOW_OBSERVATION_DESIGN.md    original eBPF Stage 0 design
INSIGHTS_AND_BRAINSTORM.md         exploratory ideas, not authoritative
GitHub Issues/PRs                  detailed historical record and evidence
```

This document remains useful as a bridge between the validated foundation and the role-fluid organism direction, but it is no longer the primary roadmap.
# Role-Fluid Agent Architecture — Roadmap and Design Intent

**Status:** Design intent captured — no implementation in this document  
**Issue:** #63  
**Author:** Dev Lead  
**Date:** 2026-05-11

---

## Summary

This document captures the architectural direction of the physarum-attack-paths project beyond the eBPF Stage 0 design. It records what has been validated, what is being built next, and where the project is going in the long term. No code is implemented here.

---

## 1. Validated foundation

Gates A through H established that the core reinforcement mechanism works under real network conditions before anything autonomous is attempted.

```text
Gate A–C    Docker weighted competing paths — Physarum scoring validated in controlled containers
Gate D–F    AWS Mode 1 runtime — agent ↔ server over real EC2 infrastructure
Gate G      AWS Mode 2 runtime — segmented lab with designated probe targets
            TLA+ B/C/D path-selection model — formal verification of autonomous path re-selection
Gate H      AWS tc/netem weighted competing paths — real network degradation, convergence in ~240 s,
            score separation Δ~5–7 % with no operator intervention
```

Gate H was the critical validation:

```text
two competing paths (B→C→D vs B→E→D) with real tc/netem degradation applied at C
system converged and re-selected the correct path autonomously
q_ema and D_ij reinforcement/decay cycle proven under real conditions
no central coordination required
```

This proven foundation is the prerequisite for everything that follows. The scoring mechanism does not change — the input signals generalize.

---

## 2. Near-term eBPF direction

The next implementation step is passive flow observation using eBPF. The design is defined in:

```text
General-Docs/EBPF_FLOW_OBSERVATION_DESIGN.md   (Issue #61 / PR #62)
```

### Current near-term process layout

```text
physarum-agent           core agent: probing, scoring, reporting
physarum-ebpf-observer   sidecar: TCP state tracepoint, metadata only
```

The sidecar is a **transitional validation design**. It is the right approach for the near term because:

- eBPF has additional kernel and runtime complexity that should be validated independently before integration into the core agent.
- The observer can be toggled, restarted, or replaced without touching the stable agent binary.
- Privilege isolation: `CAP_BPF` and `CAP_PERFMON` are confined to the sidecar; the core agent remains unprivileged.

The two-process layout is not the final architecture.

### Stage sequence for eBPF work

```text
Stage 0   Design document (Issue #61 / PR #62) ← done
Stage 1   FlowObservation model + POST/GET /flow-observations + unit tests   → Gate I
Stage 2   physarum-ebpf-observer crate; TCP state tracepoint; posts to server
Stage 3   AWS EC2 validation on Amazon Linux 2023                            → Gate J
Stage 4   Scoring integration proposal (combine probes + passive flows)      → Gate K
```

---

## 3. Future unified agent direction

After the eBPF sidecar is validated, the long-term direction is a **unified physarum-agent runtime**.

```text
near term (transitional)         future
──────────────────────────       ──────────────────────────────────────────
physarum-agent                   physarum-agent unified runtime
physarum-ebpf-observer               core agent runtime
                                     coordinator / server capability
                                     client / reporting capability
                                     eBPF observation capability
                                     RustScan / service-discovery capability
                                     Physarum scoring
                                     controlled expansion / replication logic
                                     state reconciliation logic
```

The unified binary carries all core capabilities and switches roles at runtime based on observed conditions.

---

## 4. Role-fluid agent model

The future agent is **role-fluid**: its role is not permanently fixed but adapts to the network state it observes.

### Roles an agent may assume

```text
coordinator / server      bootstraps the network, holds the authoritative graph
client / reporter         probes paths, reports scores to the coordinator
flow observer             runs the eBPF observation loop
service-discovery worker  runs RustScan-backed port enumeration on candidate hosts
path scorer               computes q_ema / D_ij for its local edges
expansion unit            propagates to the next highest-scored node
local recovery            if upstream coordinator is unreachable, assumes coordinator role
```

### Role transition example

```text
Initial state:
  machine A = seed / coordinator agent

Expansion:
  A propagates agents to B and C
  B and C initially report to A as clients

Role transition:
  B loses the flow / path to A
  B promotes itself to local coordinator
  B continues expansion from its current position
  the organism continues to grow from B's foothold
```

This matches the Physarum analogy:

```text
spread through the maze
reinforce useful channels
abandon weak / dead paths
continue growing from viable points even when the original seed point is isolated
```

### Core conceptual principle

```text
Agents are not only observers of paths.
Agents are the computational substance that occupies and reinforces paths.
```

---

## 5. RustScan as a future agent capability

RustScan (Rust, MIT licensed) is the identified tool for service-discovery experiments in a future gate.

### Intended role

```text
eBPF passive flow evidence identifies candidate destinations worth probing.
RustScan enumerates all open TCP ports at those destinations.
Port discovery results feed into the physarum graph as candidate edges and nodes.
```

### Integration model

```text
RustScan embedded as a library dependency inside physarum-agent
not called as an external subprocess
port discovery results → candidate observations → physarum graph edges
```

### Semantic rule

```text
Open ports are exposure observations, not proof of authorized access or exploitability.
```

RustScan discovery results are observations that enrich the graph. They do not grant authorization or imply that the agent may proceed without operator-defined scope.

**RustScan integration is not part of the current eBPF Stage 0/Stage 1 work. It is a future gate.**

---

## 6. Controlled Physarum-inspired expansion

The project models agents as computational analogues of Physarum polycephalum. In controlled environments, agents may eventually use passive flow evidence and service-discovery evidence to identify candidate next steps, reinforce productive paths, and decay weaker or unproductive paths.

### Autonomous propagation cycle (future)

```text
1. eBPF observer detects passive flows to reachable hosts
        → port 80/443 flow seen = traversable signal = candidate to explore

2. RustScan enumerates all open TCP ports at the discovered host
        → not only the obvious ports

3. Physarum scoring (q_ema / D_ij) ranks available paths
        → strongest filament = highest scored path = where the agent goes next

4. Agent propagates to the next node and repeats from there
        → graph expands dynamically at runtime
        → no pre-defined topology, no pre-provisioned agent nodes
        → emergent network map built by the agent itself

5. Weak paths decay (q_ema drops), dead ends are abandoned
        → the agent self-organizes around reachable, productive paths
```

### How q_ema / D_ij generalizes to the autonomous model

The scoring formula does not change. The input signals generalize:

```text
eBPF flow frequency     → more observed flows to a host = stronger edge signal
RustScan result         → useful open ports found = positive reinforcement
Propagation outcome     → agent reached the node successfully = q_ema rises
Dead end                → no open ports, no propagation path = q_ema decays, edge removed
New node discovered     → edge bootstraps at q_ema=0, grows with evidence
```

---

## 7. Intended sequence

```text
1. eBPF passive flow observation first          (near term — Gate I / Gate J)
2. RustScan as a library for service discovery  (future gate)
3. Controlled Physarum-inspired expansion       (future gate — after scoring integration)
```

---

## 8. What this document does NOT authorize

```text
eBPF code                  → defined in EBPF_FLOW_OBSERVATION_DESIGN.md, implemented in Gate J
RustScan integration       → future gate, not implemented in eBPF Stage 0/1
Role-fluid runtime         → future gate, not implemented in eBPF Stage 0/1
Scoring changes            → Stage 4 only, after passive evidence is validated
Uncontrolled propagation   → never; expansion is always operator-scoped
```

---

## 9. Relationship to existing design documents

```text
EBPF_FLOW_OBSERVATION_DESIGN.md    Stage 0 design — sidecar, Aya stack, TCP state tracepoint
PROTOTYPE_ROADMAP.md               Gate history and milestone tracking
QUALITY_GATE.md                    Gate definitions and acceptance criteria
INSIGHTS_AND_BRAINSTORM.md         Exploratory ideas (not authoritative)
```

This document is the architectural bridge between the validated foundation (Gates A–H) and the future autonomous agent direction.

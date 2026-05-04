# Prototype Roadmap — Physarum Attack Paths

This document defines the prototype roadmap for `physarum-attack-paths`.

The project started as a local A/B/C laboratory with one coordinator and two agents. It has now evolved into a working adaptive graph prototype with local execution, Docker reproducibility, stimulus-oriented reports, a formal TLA+ edge model, a basic adaptive path scoring endpoint (`GET /paths`), and a documented contribution workflow.

The guiding principle remains:

```text
Make it work.
Make it observable.
Make it reproducible.
Make it formally understandable.
Make it realistic.
Make it secure.
Make it production-grade.
```

---

## 1. Current project status

### Completed

```text
Phase 1A — Server-side graph loop
Phase 1B — Minimal physarum-agent
Phase 1C — Stimulus-oriented ProbeReport, Q_ij, q_ema, and D_ij
Local A/B/C lab runbook
Docker A/B/C lab (validated: 15 passed, 0 failed)
TLA+ initial edge model — TypeOK and Safety verified by TLC
README refresh — root README aligned with current prototype state
Docker A/B/C/D lab (validated: 34 passed, 0 failed)
GET /paths — bounded DFS, score = product(d_ij), sorted descending
Documentation workflow — PR/issue templates and ownership guidelines
AWS lab — test-plan documentation only, no Terraform yet
WASM lab — visual-simulation plan documentation only
```

### In progress / planned next

```text
AWS Terraform skeleton / AWS lab implementation planning
```

### Planned, not started

```text
WASM visual simulator implementation
TLA+ expansion beyond one edge
security hardening
persistence
MCPM-inspired stochastic path-density exploration
TOON export
```

---

## 2. Current repository structure

```text
physarum-attack-paths/
├── Cargo.toml
├── Dockerfile
├── crates/
│   ├── physarum-protocol/
│   ├── physarum-server/
│   └── physarum-agent/
├── examples/
│   ├── local-lab/
│   │   ├── README.md
│   │   └── check-local-lab.sh
│   ├── docker-lab/
│   │   ├── README.md
│   │   ├── docker-compose.yml
│   │   └── check-docker-lab.sh
│   ├── aws-lab/
│   │   └── README.md
│   └── wasm-lab/
│       └── README.md
├── General-Docs/
│   ├── PROTOTYPE_ROADMAP.md
│   ├── DOCUMENTATION_GUIDELINES.md
│   └── INSIGHTS_AND_BRAINSTORM.md
└── formal/
    └── tla/
        ├── README.md
        ├── PhysarumEdgeModel.tla
        └── PhysarumEdgeModel.cfg
```

---

## 3. Core architecture as implemented

```text
A = physarum-server / coordinator
B = physarum-agent / agent-b
C = physarum-agent / agent-c
D = physarum-agent / agent-d
```

The Docker lab runs B, C, and D in a full mesh: each agent probes all others, producing six directed edges.

Logical flow:

```text
agents register with server
agents fetch peers
agents probe peers
agents maintain short-term observation windows
agents send enriched ProbeReport messages
server computes Q_ij
server smooths Q_ij into q_ema
server updates D_ij
server exposes /graph and /paths
```

Current signal flow:

```text
local observation window -> enriched ProbeReport -> Q_ij -> q_ema -> D_ij -> path_score
```

Path scoring:

```text
/paths returns all simple paths from source to target
path_score = product(d_ij) for all edges in the path
paths are sorted by score descending
in a full-mesh lab, the direct agent-b -> agent-d path may rank above
agent-b -> agent-c -> agent-d depending on live d_ij values
```

Interpretation:

```text
agent = short-term local sensory organ
ProbeReport = stimulus
q_ema = smoothed stimulus memory
D_ij = adaptive edge conductivity
path_score = composite adaptive path quality
server graph = longer-term adaptive morphology
```

---

## 4. Implemented crates

### `physarum-protocol`

Shared types used by the server and agents.

```text
AgentId, AgentInfo, RegisterRequest, RegisterResponse
PeerInfo, ProbeReport
GraphSnapshot, EdgeSnapshot
PathEdge, PathResult, PathsResponse
```

`ProbeReport` is stimulus-oriented and includes recent-window statistics:

```text
success, rtt_ms, success_rate, avg_rtt_ms, jitter_ms
observation_window_seconds, sample_count, observed_at
```

`EdgeSnapshot` includes adaptive morphology fields:

```text
probe_success, d_ij, q_ema
success_rate, avg_rtt_ms, jitter_ms, sample_count, last_seen
```

### `physarum-server`

Coordinator process. Computes Q_ij → q_ema → D_ij per directed edge and maintains the graph in memory.

Current endpoints:

```text
GET  /health
POST /register
GET  /agents
GET  /peers/:agent_id
POST /report
GET  /graph
GET  /paths?source=...&target=...&max_depth=...
```

### `physarum-agent`

Agent process. Maintains a bounded sliding window per peer (WINDOW_SIZE = 20) and sends enriched `ProbeReport` events to the coordinator.

Derived values per window:

```text
success_rate = successful samples / samples.len()
avg_rtt_ms = mean RTT over successful samples
jitter_ms = mean absolute deviation over successful RTT samples
sample_count = samples.len(), capped at 20
```

---

## 5. Adaptive edge model

```text
local observation window -> Q_ij -> q_ema -> D_ij
```

### Latency score

```text
latency_score = 1.0 / (1.0 + avg_rtt_ms / 100.0)
```

### Normalized stimulus

```text
if success_rate == 0.0:
    Q_ij = 0.0
else:
    Q_ij = clamp(0.7 * success_rate + 0.3 * latency_score, 0.0, 1.0)
```

### EMA update

```text
q_ema(t+1) = 0.3 * Q_ij + 0.7 * q_ema(t)
```

### Physarum conductivity update

```text
f(x) = x² / (1 + x²)
D_ij(t+1) = D_ij(t) + f(q_ema) * (1 - D_ij(t)) - r * D_ij(t)
r = 0.1
D_ij is clamped to [0.0, 1.0]
```

Under stable successful low-latency probes, the observed equilibrium approaches:

```text
D_ij ≈ 5/6 ≈ 0.833
```

---

## 6. Labs

### 6.1 Local lab — implemented

```text
examples/local-lab/
```

Manual A/B/C execution with multiple terminals. See [examples/local-lab/README.md](../examples/local-lab/README.md) for the full runbook.

### 6.2 Docker lab — implemented and validated

```text
examples/docker-lab/
```

Reproducible A/B/C/D runtime test. Single-command deployment. See [examples/docker-lab/README.md](../examples/docker-lab/README.md) for the full runbook.

Validates 34 checks: 1 health + 3 agent registrations + 6 directed edges × 5 assertions each.

```bash
cd examples/docker-lab
docker compose up --build
bash check-docker-lab.sh
curl -s 'http://127.0.0.1:8080/paths?source=agent-b&target=agent-d' | jq
```

```text
Results: 34 passed, 0 failed
```

### 6.3 AWS lab — planned, documented only

```text
examples/aws-lab/
```

Future EC2/VPC/subnet validation for real cloud network behavior. No Terraform yet.

### 6.4 WASM lab — planned, documented only

```text
examples/wasm-lab/
```

Future visual simulator for Q_ij, q_ema, and D_ij dynamics.

```text
Docker = runtime reproducibility
AWS = network realism
WASM = visual explanation
TLA+ = formal reasoning
```

---

## 7. Formal methods track

```text
formal/tla/
├── README.md
├── PhysarumEdgeModel.tla
└── PhysarumEdgeModel.cfg
```

The model represents one directed edge and formalizes `ProbeReport -> Q_ij -> q_ema -> D_ij`.

Scaled integer arithmetic (SCALE = 1000) represents [0.0, 1.0] values for TLC model checking.

Verified invariants:

```text
TypeOK: q_ema ∈ 0..SCALE ∧ d_ij ∈ 0..SCALE
Safety: QEmaBounded ∧ DijBounded (both stay in [0, SCALE] for all reachable states)
```

Status: completed. TLC finds no violations with SCALE=1000.

Future formal methods work (not started):

```text
TLA+ expansion beyond one edge
multi-agent concurrency model
coordinator graph state
path traversal properties
```

---

## 8. Completed milestones

| Milestone | Key deliverable |
|---|---|
| Phase 1A (Issue #1) | Server graph loop, D_ij model, initial tests |
| Phase 1B (Issue #3) | `physarum-agent`, first A/B/C distributed loop |
| Local A/B/C lab (Issue #5) | `examples/local-lab/`, validation script |
| Phase 1C (Issue #7) | Stimulus-oriented `ProbeReport`, Q_ij, q_ema, D_ij |
| Docker A/B/C lab (Issue #9) | Dockerfile, Compose, 15-check validation |
| TLA+ edge model (Issue #11) | `PhysarumEdgeModel.tla`, TypeOK + Safety verified |
| README refresh (Issue #13) | Root README aligned with prototype state |
| A/B/C/D design (Issue #15) | Topology design documented |
| Docker A/B/C/D lab (Issue #16) | `agent-d` added to Compose, 34-check validation |
| GET /paths (Issue #17) | Bounded DFS, `score = product(d_ij)`, sorted results, 8 new tests |
| Documentation workflow (Issue #22) | PR/issue templates, `DOCUMENTATION_GUIDELINES.md` |

Detailed delivery history lives in the corresponding GitHub Issues and PRs.

---

## 9. Recommended next implementation order

```text
✔ 1. Complete Issue #11: initial TLA+ model for Q_ij, q_ema, D_ij.
✔ 2. Align root README with current prototype state (Issue #13).
✔ 3. Design A/B/C/D lab topology and path-readiness plan (Issue #15).
✔ 4. Implement Docker A/B/C/D lab (Issue #16).
✔ 5. Add basic /paths endpoint using D_ij and q_ema (Issue #17).
  6. Create AWS Terraform skeleton only after the A/B/C/D and /paths direction is clear.
  7. Implement WASM visual simulator when the math is stable enough to present.
  8. Add security controls: enrollment, signatures, replay protection, optional mTLS.
  9. Add persistence and replay.
 10. Explore MCPM-inspired stochastic path-density engine.
 11. Add TOON export and integration with autonomous validation workflows.
```

Do not jump directly to eBPF, AWS infrastructure, or path-density simulation before the current adaptive graph substrate is stable and formally documented.

---

## 10. A/B/C/D topology

The Docker lab implements a full-mesh A/B/C/D topology.

### Agent roles

```text
A = physarum-server (coordinator)
B = agent-b — perimeter-like / entry-layer agent
C = agent-c — application/gateway-like agent
D = agent-d — crown-jewel/database-like agent
```

### Local port assignments

```text
physarum-server  127.0.0.1:8080
agent-b          127.0.0.1:9001
agent-c          127.0.0.1:9002
agent-d          127.0.0.1:9003
```

### Graph behavior

The coordinator returns all registered agents as peers (full mesh). Six directed edges form:

```text
agent-b -> agent-c      agent-c -> agent-b
agent-b -> agent-d      agent-d -> agent-b
agent-c -> agent-d      agent-d -> agent-c
```

`/paths?source=agent-b&target=agent-d` returns both the direct path (B→D) and the two-hop path (B→C→D). Ranking depends on live `d_ij` values — the direct hop may outscore the two-hop path if its conductivity is higher.

The key transition this topology enables:

```text
adaptive edge (D_BC)  →  adaptive path (score = product of d_ij per hop)
```

Constrained peer sets (security groups, topological filtering) will be introduced in a later phase to model realistic network segmentation.

---

## 11. Future security controls

After the graph loop and path scoring are stable, add:

```text
agent enrollment tokens
Ed25519 report signatures
monotonic nonces
replay protection
coordinator certificate pinning
optional mTLS
```

---

## 12. Future eBPF telemetry

Only after the probe/report/graph/path loop is stable, add eBPF to observe real TCP flows and feed them into Q_ij:

```text
Q_ij = w1 * Probe(i,j) + w2 * Observe(i,j)
```

---

## 13. Future persistence and replay

Persist probe reports, Q_ij, q_ema, D_ij, and graph snapshots to allow reconstructing the adaptive graph from historical data. SQLite for prototype simplicity; ClickHouse for time-series scale.

---

## 14. Future MCPM-inspired path density

Details in [General-Docs/INSIGHTS_AND_BRAINSTORM.md](INSIGHTS_AND_BRAINSTORM.md).

Future concept: simulated agents explore the adaptive graph morphology and path-density estimates emerge from repeated stochastic traversal. Not near-term work — revisit after basic path scoring is stable.

---

## 15. Future TOON export

Once path scoring is validated, expose `GET /toon/{target}` connecting the prototype to upstream autonomous validation and attack-path probability modeling.

---

## 16. Roadmap philosophy

One issue = one small capability. Runtime changes and research ideas stay separate. Labs validate behavior before infrastructure expands. Formal models protect core assumptions.

The project is now beyond a pure concept. It has a working adaptive A/B/C/D prototype with Docker reproducibility, a basic adaptive path scoring endpoint, and a clear path toward realistic AWS validation.

# Prototype Roadmap — Physarum Attack Paths

This document defines the prototype roadmap for `physarum-attack-paths`.

The project started as a local A/B/C laboratory with one coordinator and two agents. It has now evolved into a working adaptive graph prototype with local execution, Docker reproducibility, stimulus-oriented reports, a formal TLA+ edge model, and a clear path toward the first multi-hop path scoring endpoint.

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
Docker A/B/C/D lab (Issue #16, validated: 34 passed, 0 failed)
GET /paths — adaptive path scoring, DFS, product(d_ij) score (Issue #17)
Research/brainstorm notes for MCPM-inspired future path density
AWS lab test-plan documentation
WASM lab visual-simulation plan
```

### In progress / planned next

```text
(none)
```

### Planned, not started

```text
AWS Terraform skeleton
WASM visual simulator implementation
TLA+ expansion beyond one edge
security hardening
persistence
MCPM-inspired stochastic path-density exploration
TOON export
```

---

## 2. Current repository structure

The repository is now organized around code, labs, documentation, brainstorm notes, and future formal models.

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
│   └── INSIGHTS_AND_BRAINSTORM.md
└── formal/
    └── tla/                  # planned by Issue #11
        ├── README.md
        ├── PhysarumEdgeModel.tla
        └── PhysarumEdgeModel.cfg
```

---

## 3. Core architecture as implemented

The current implemented architecture uses:

```text
A = physarum-server / coordinator
B = physarum-agent / agent-b
C = physarum-agent / agent-c
```

Logical flow:

```text
agent-b registers with server
agent-c registers with server
agents fetch peers
agents probe peers
agents maintain short-term observation windows
agents send enriched ProbeReport messages
server computes Q_ij
server smooths Q_ij into q_ema
server updates D_ij
server exposes /graph
```

Current signal flow:

```text
local observation window -> enriched ProbeReport -> Q_ij -> q_ema -> D_ij
```

Interpretation:

```text
agent = short-term local sensory organ
ProbeReport = stimulus
q_ema = smoothed stimulus memory
D_ij = adaptive edge conductivity
server graph = longer-term adaptive morphology
```

---

## 4. Implemented crates

### `physarum-protocol`

Shared types used by the server and agents.

Important concepts:

```text
AgentId
AgentInfo
RegisterRequest
RegisterResponse
PeerInfo
ProbeReport
GraphSnapshot
EdgeSnapshot
```

`ProbeReport` is now stimulus-oriented and includes recent-window statistics:

```text
success
rtt_ms
success_rate
avg_rtt_ms
jitter_ms
observation_window_seconds
sample_count
observed_at
```

`EdgeSnapshot` includes adaptive morphology fields:

```text
probe_success
d_ij
q_ema
success_rate
avg_rtt_ms
jitter_ms
sample_count
last_seen
```

### `physarum-server`

Coordinator process.

Responsibilities:

```text
accept agent registration
track active agents
return peer lists
receive enriched probe reports
compute Q_ij
update q_ema
update D_ij
maintain directed graph edges in memory
expose graph inspection endpoints
```

Current main endpoints:

```text
GET  /health
POST /register
GET  /agents
GET  /peers/:agent_id
POST /report
GET  /graph
```

### `physarum-agent`

Agent process.

Responsibilities:

```text
start with configured agent_id
register with coordinator
expose local /probe endpoint
fetch peers from coordinator
probe peers periodically
maintain bounded per-peer observation windows
compute local statistics
send enriched ProbeReport events to coordinator
```

Each peer observation uses a bounded sliding window:

```text
WINDOW_SIZE = 20
samples = VecDeque<ProbeSample>
ProbeSample.success = probe success/failure
ProbeSample.rtt_ms = RTT for successful probes, None for failures
```

Derived values:

```text
success_rate = successful samples / samples.len()
avg_rtt_ms = mean RTT over successful samples
jitter_ms = mean absolute deviation over successful RTT samples
sample_count = samples.len(), capped at 20
```

---

## 5. Adaptive edge model

The implemented adaptive edge model follows:

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

Path:

```text
examples/local-lab/
```

Purpose:

```text
manual A/B/C execution with multiple terminals
simple local debugging
clear first-time runbook
```

Typical execution:

```bash
cargo run -p physarum-server -- --listen 127.0.0.1:8080
cargo run -p physarum-agent -- --id agent-b --coordinator http://127.0.0.1:8080 --listen 127.0.0.1:9001 --advertise-address 127.0.0.1 --probe-interval-seconds 5
cargo run -p physarum-agent -- --id agent-c --coordinator http://127.0.0.1:8080 --listen 127.0.0.1:9002 --advertise-address 127.0.0.1 --probe-interval-seconds 5
bash examples/local-lab/check-local-lab.sh
```

### 6.2 Docker lab — implemented and validated

Path:

```text
examples/docker-lab/
```

Purpose:

```text
reproducible A/B/C runtime test
single-command local deployment
fast developer validation
```

Typical execution:

```bash
cd examples/docker-lab
docker compose up --build
bash check-docker-lab.sh
```

The Docker lab validates:

```text
/health returns ok
agent-b and agent-c register
agent-b and agent-c discover each other
agent-b -> agent-c exists
agent-c -> agent-b exists
probe_success == true
q_ema > 0.0
D_ij > 0.0
sample_count > 0
```

Observed Docker validation:

```text
Results: 15 passed, 0 failed
```

### 6.3 AWS lab — planned, documented only

Path:

```text
examples/aws-lab/
```

Purpose:

```text
future EC2/VPC/subnet/security-group validation
real cloud network behavior
controlled asymmetric reachability
foundation for future A/B/C/D path testing
```

Current status:

```text
Documentation only.
No Terraform yet.
```

AWS should be used later to validate:

```text
real subnet boundaries
security group changes
asymmetric reachability
D_ij decay when traffic is blocked
q_ema recovery when traffic is restored
```

### 6.4 WASM lab — planned, documented only

Path:

```text
examples/wasm-lab/
```

Purpose:

```text
future visual simulator for Q_ij, q_ema, and D_ij dynamics
human-readable demonstration of adaptive morphology
architecture/patent/research communication aid
```

Current status:

```text
Documentation only.
No WASM implementation yet.
```

WASM should not replace Docker or AWS.

```text
Docker = runtime reproducibility
AWS = network realism
WASM = visual explanation
TLA+ = formal reasoning
```

---

## 7. Formal methods track

The initial TLA+ model was delivered by Issue #11 / PR #12.

Path:

```text
formal/tla/
```

Files delivered:

```text
formal/tla/README.md
formal/tla/PhysarumEdgeModel.tla
formal/tla/PhysarumEdgeModel.cfg
```

The model represents one directed edge and formalizes the adaptive edge dynamics:

```text
ProbeReport fields -> Q_ij -> q_ema -> D_ij
```

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

### Issue #1 — Phase 1A: server-side graph loop

Status:

```text
completed
```

Delivered:

```text
GET /peers/:agent_id
POST /report
GET /graph
in-memory directed edges
basic D_ij reinforcement/decay model
tests for peers, reports, graph, bounds
```

### Issue #2 — CI formatting fix

Status:

```text
completed
```

Delivered:

```text
identified rustfmt drift as CI failure cause
kept Axum route syntax unchanged
applied formatting-only fix
```

### Issue #3 / PR #4 — minimal physarum-agent

Status:

```text
completed and merged
```

Delivered:

```text
crates/physarum-agent
agent registration
local /probe endpoint
peer discovery
peer probing
ProbeReport sending
first A/B/C distributed loop
```

### Issue #5 / PR #6 — local A/B/C lab runbook

Status:

```text
completed and merged
```

Delivered:

```text
examples/local-lab/README.md
examples/local-lab/check-local-lab.sh
manual A/B/C validation flow
expected graph output
troubleshooting
```

### Issue #7 / PR #8 — stimulus-oriented reporting

Status:

```text
completed and merged
```

Delivered:

```text
bounded peer observation window in agent
enriched ProbeReport
Q_ij calculation
q_ema update
D_ij driven by q_ema
extended /graph edge fields
updated local-lab and roadmap docs
39 tests reported
```

### Issue #9 / PR #10 — Docker A/B/C lab

Status:

```text
completed and merged
```

Delivered:

```text
Dockerfile
examples/docker-lab/docker-compose.yml
examples/docker-lab/check-docker-lab.sh
updated examples/docker-lab/README.md
runtime validation with 15 passed, 0 failed
```

---

## 9. Completed milestones (summary)

Issues #11, #13, #15, #16, and #17 are all closed and merged.

### Issue #11 / PR #12 — initial TLA+ edge model

Status: `completed`

Delivered: `formal/tla/PhysarumEdgeModel.tla`, TypeOK and Safety invariants verified by TLC.

### Issue #13 — README refresh

Status: `completed`

Delivered: root README rewritten to reflect current prototype state.

### Issue #15 — A/B/C/D lab design

Status: `completed`

Delivered: A/B/C/D topology design in PROTOTYPE_ROADMAP.md and local-lab README.

### Issue #16 — Docker A/B/C/D lab

Status: `completed`

Delivered: `agent-d` added to Compose; `check-docker-lab.sh` validates 34 checks (1 health + 3 registration + 6 edges × 5).

### Issue #17 — GET /paths endpoint

Status: `completed`

Delivered:
- Protocol types: `PathEdge`, `PathResult`, `PathsResponse` in `physarum-protocol`
- Route `GET /paths?source=…&target=…&max_depth=…` in `physarum-server/src/routes/paths.rs`
- DFS path search, cycle-safe, sorted by `score = product(d_ij)` descending
- 8 new tests (47 workspace tests total)
- Documentation updated in README.md, PROTOTYPE_ROADMAP.md, docker-lab README

---

## 11. Recommended next implementation order

The recommended near-term sequence is:

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

## 12. A/B/C/D topology design

This section documents the A/B/C/D topology that will be implemented in Issue #16 (Docker lab) and exercised by Issue #17 (/paths endpoint).

### Agent roles

```text
A = physarum-server (coordinator)
B = agent-b — perimeter-like / entry-layer agent
C = agent-c — application/gateway-like agent
D = agent-d — crown-jewel/database-like agent
```

### Why this matters

```text
B ↔ C only proves one adaptive edge pair.
B/C/D creates a meaningful multi-hop path.
B → C → D is the simplest useful path for scoring.
```

The key transition is:

```text
adaptive edge (D_BC)  →  adaptive path (D_BC * D_CD)
```

### Local port assignments

```text
physarum-server  127.0.0.1:8080
agent-b          127.0.0.1:9001
agent-c          127.0.0.1:9002
agent-d          127.0.0.1:9003
```

### Docker service names

```text
physarum-server
agent-b
agent-c
agent-d
```

### Expected graph behavior

The current coordinator returns all registered agents as peers for any requesting agent (full mesh). In the A/B/C/D lab this means six directed edges will form:

```text
agent-b -> agent-c      (path-readiness edge)
agent-c -> agent-b
agent-b -> agent-d
agent-d -> agent-b
agent-c -> agent-d      (path-readiness edge)
agent-d -> agent-c
```

Full-mesh behavior is acceptable for this phase. Constrained peer sets (security groups, topological filtering) will be introduced in a later phase to model realistic network segmentation.

The path-readiness focus is on the logical attack path:

```text
agent-b → agent-c → agent-d
```

### Validation expectations for A/B/C/D

A complete A/B/C/D validation should check:

```text
agent-b registered
agent-c registered
agent-d registered
/graph nodes include agent-b, agent-c, agent-d
agent-b -> agent-c: probe_success=true, q_ema>0.0, d_ij>0.0, sample_count>0
agent-c -> agent-d: probe_success=true, q_ema>0.0, d_ij>0.0, sample_count>0
```

If full mesh: all six directed edges meet the same criteria.

### Future /paths contract

After Issue #17 is implemented, the endpoint will be:

```text
GET /paths?source=agent-b&target=agent-d
```

Conceptual response:

```json
{
  "source": "agent-b",
  "target": "agent-d",
  "paths": [
    {
      "nodes": ["agent-b", "agent-c", "agent-d"],
      "edges": [
        { "source": "agent-b", "target": "agent-c", "d_ij": 0.833, "q_ema": 1.0 },
        { "source": "agent-c", "target": "agent-d", "d_ij": 0.833, "q_ema": 1.0 }
      ],
      "score": 0.694
    }
  ]
}
```

Initial scoring rule:

```text
path_score = product(D_ij for each edge in the path)
           = D_BC * D_CD
           = 0.833 * 0.833
           ≈ 0.694
```

Future scoring inputs (not in the initial version):

```text
L_ij resistance (layer transition cost, service exposure)
vulnerability pressure (CVSS, EPSS, KEV)
asset criticality
MCPM-inspired stochastic path density
```

---

## 13. Future A/B/C/D direction *(superseded by Section 12 above)*

The next topology expansion should be:

```text
A = coordinator / physarum-server
B = perimeter-like agent
C = application/gateway-like agent
D = crown-jewel/database-like agent
```

This topology will make path scoring meaningful.

Example path:

```text
B -> C -> D
```

Future basic path score:

```text
path_score = product(D_ij)
```

or:

```text
path_score = product(D_ij / L_ij)
```

For the first version:

```text
L_ij = 1.0
```

Later, `L_ij` may incorporate:

```text
layer transition cost
service exposure
vulnerability pressure
asset criticality
credential/trust signal
```

---

## 12. Future security controls

After the graph loop and path scoring are stable, add:

```text
agent enrollment tokens
Ed25519 report signatures
monotonic nonces
replay protection
coordinator certificate pinning
optional mTLS
```

The goal is to prevent:

```text
fake reports
replayed reports
unauthorized agents
unauthorized graph manipulation
```

---

## 13. Future eBPF telemetry

Only after the probe/report/graph/path loop is stable, add eBPF.

Initial eBPF goals:

```text
observe TCP connection state changes
count flows between local agent and peer IPs
export flow counts to user space
include observed flow signal in Q_ij
```

Possible future formula:

```text
Q_ij = w1 * Probe(i,j) + w2 * Observe(i,j)
```

Later:

```text
Q_ij = w1 * Probe(i,j) + w2 * Validation(i,j) + w3 * Observe(i,j)
```

---

## 14. Future persistence and replay

Persistence should come after the coordinator behavior is stable.

Possible first options:

```text
SQLite for local prototype simplicity
ClickHouse for time-series behavior closer to the final architecture
```

Persist:

```text
agent registrations
probe reports
Q_ij values
q_ema values
D_ij over time
graph snapshots
drift events
```

Replay should allow reconstructing the adaptive graph from historical reports.

---

## 15. Future MCPM-inspired path density

The idea is documented in:

```text
General-Docs/INSIGHTS_AND_BRAINSTORM.md
```

Future concept:

```text
real agents provide evidence
server builds adaptive graph morphology
simulated agents explore that graph
path-density estimates emerge from repeated stochastic traversal
```

This is not near-term implementation work.

It should be revisited only after:

```text
A/B/C/D works
/paths exists
basic path scoring is stable
```

---

## 16. Future TOON export

Once graph behavior and path scoring are validated, add TOON export.

Possible endpoint:

```text
GET /toon/{target}
```

Potential fields:

```text
source
target
ports
p_v
p_e
d_ij
q_ema
path_score
layer_emergent
layer_declared
data_completeness
```

This phase connects the prototype to upstream autonomous validation and attack-path probability modeling.

---

## 17. Roadmap philosophy

The project should continue with baby steps.

The current priority is not to add complexity. The current priority is to make the adaptive graph substrate reliable, reproducible, explainable, and formally understandable.

Recommended discipline:

```text
one issue = one small capability
runtime changes and research ideas stay separate
labs validate behavior before infrastructure expands
formal models protect core assumptions
visual simulators explain the model but do not replace runtime tests
AWS validates realism only after local and Docker behavior are stable
```

The project is now beyond a pure concept. It has a working adaptive A/B/C prototype, a reproducible Docker lab, and a clear path toward formal modeling, A/B/C/D, path scoring, and eventually realistic AWS validation.

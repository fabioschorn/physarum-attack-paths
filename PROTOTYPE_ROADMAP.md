# Prototype Roadmap — Local A/B/C Laboratory

This document defines the first practical prototype for `physarum-attack-paths`.

The goal is to build a minimal but functional local laboratory with one coordinator server and two agents. This prototype intentionally starts without eBPF, attestation, mTLS, ClickHouse, or production hardening. The purpose is to validate the core idea first: agents observe reachability, report evidence to a coordinator, and the coordinator turns that evidence into a living attack-path graph with dynamic edge conductivity.

---

## 1. Prototype topology

The initial test environment uses three machines, virtual machines, or containers:

```text
A = Coordinator / Server
B = Agent
C = Agent
```

Recommended local IP layout:

```text
A - 192.168.56.10 - physarum-server
B - 192.168.56.11 - physarum-agent
C - 192.168.56.12 - physarum-agent
```

Logical topology:

```text
        ┌──────────────────────┐
        │ A - Coordinator       │
        │ API + Graph Engine    │
        └──────────┬───────────┘
                   ▲
          reports  │  reports
                   │
     ┌─────────────┴─────────────┐
     │                           │
     ▼                           ▼
┌──────────────┐           ┌──────────────┐
│ B - Agent    │◄─────────►│ C - Agent    │
│ probe peer   │           │ probe peer   │
│ report to A  │           │ report to A  │
└──────────────┘           └──────────────┘
```

---

## 2. Prototype objective

The first objective is not to prove exploitation or lateral movement.

The first objective is to prove that:

> Two distributed agents can discover basic peer reachability, report observations to a coordinator, and allow the coordinator to maintain a dynamic graph whose edge conductivity changes over time.

This validates the core mechanism before adding eBPF, cryptographic attestation, advanced path search, or autonomous validation agents.

---

## 3. Prototype scope

### Included in Phase 0

- One coordinator server.
- Two agents.
- Agent registration.
- Peer discovery through the coordinator.
- Simple HTTP/TCP-based peer probe.
- Periodic reports from agents to coordinator.
- In-memory graph on the coordinator.
- Dynamic edge conductivity update using reinforcement and decay.
- JSON API to inspect agents, edges, and graph state.
- Basic logs for debugging and observability.

### Explicitly excluded from Phase 0

- eBPF flow capture.
- Kernel telemetry.
- mTLS.
- Ed25519 report signatures.
- TPM/Nitro/Azure/GCP attestation.
- ClickHouse persistence.
- Multi-coordinator federation.
- Kubernetes Helm deployment.
- Terraform deployment.
- TOON export.
- Autonomous pentest orchestration.

These features are intentionally deferred so the first prototype remains small, testable, and easy to debug.

---

## 4. Repository structure for the MVP

Recommended structure:

```text
physarum-attack-paths/
├── Cargo.toml
├── crates/
│   ├── physarum-protocol/
│   ├── physarum-server/
│   └── physarum-agent/
├── examples/
│   └── local-lab/
│       ├── README.md
│       └── docker-compose.yml
└── PROTOTYPE_ROADMAP.md
```

### `physarum-protocol`

Shared types used by the server and agents.

Initial data structures:

```text
AgentId
AgentInfo
RegisterRequest
RegisterResponse
PeerInfo
ProbeResult
ProbeReport
GraphSnapshot
EdgeSnapshot
```

### `physarum-server`

Coordinator process.

Responsibilities:

- Accept agent registration.
- Track active agents.
- Return peer lists.
- Receive probe reports.
- Maintain the graph in memory.
- Update edge conductivity.
- Expose graph inspection endpoints.

### `physarum-agent`

Agent process.

Responsibilities:

- Start with a configured `agent_id`.
- Register itself with the coordinator.
- Fetch the current peer list.
- Probe peers periodically.
- Report probe results to the coordinator.
- Log local probe outcomes.

---

## 5. Coordinator API for Phase 0

The first server should expose the following minimal API:

```text
POST /register
GET  /agents
GET  /peers/{agent_id}
POST /report
GET  /graph
GET  /health
```

### `POST /register`

Registers an agent.

Example request:

```json
{
  "agent_id": "agent-b",
  "address": "192.168.56.11",
  "probe_port": 9001
}
```

Example response:

```json
{
  "registered": true,
  "agent_id": "agent-b"
}
```

### `GET /agents`

Returns all known agents.

Example response:

```json
[
  {
    "agent_id": "agent-b",
    "address": "192.168.56.11",
    "probe_port": 9001,
    "last_seen": "2026-05-02T15:00:00Z"
  },
  {
    "agent_id": "agent-c",
    "address": "192.168.56.12",
    "probe_port": 9001,
    "last_seen": "2026-05-02T15:00:03Z"
  }
]
```

### `GET /peers/{agent_id}`

Returns all agents except the requesting agent.

Example:

```text
GET /peers/agent-b
```

Example response:

```json
[
  {
    "agent_id": "agent-c",
    "address": "192.168.56.12",
    "probe_port": 9001
  }
]
```

### `POST /report`

Receives a probe result from an agent.

Example request:

```json
{
  "source": "agent-b",
  "target": "agent-c",
  "success": true,
  "rtt_ms": 7,
  "observed_at": "2026-05-02T15:00:10Z"
}
```

### `GET /graph`

Returns the current graph snapshot.

Example response:

```json
{
  "nodes": [
    "agent-b",
    "agent-c"
  ],
  "edges": [
    {
      "source": "agent-b",
      "target": "agent-c",
      "probe_success": true,
      "d_ij": 0.72,
      "last_seen": "2026-05-02T15:00:10Z"
    },
    {
      "source": "agent-c",
      "target": "agent-b",
      "probe_success": true,
      "d_ij": 0.69,
      "last_seen": "2026-05-02T15:00:11Z"
    }
  ]
}
```

---

## 6. Agent behavior for Phase 0

Each agent runs the following loop:

```text
1. Load configuration.
2. Register with coordinator.
3. Fetch peer list from coordinator.
4. For each peer:
   4.1 Run a simple probe.
   4.2 Measure success/failure.
   4.3 Measure RTT if successful.
5. Send probe report to coordinator.
6. Sleep for probe_interval.
7. Repeat.
```

Example command for Agent B:

```bash
physarum-agent \
  --id agent-b \
  --coordinator http://192.168.56.10:8080 \
  --listen 0.0.0.0:9001 \
  --advertise-address 192.168.56.11 \
  --probe-interval 10s
```

Example command for Agent C:

```bash
physarum-agent \
  --id agent-c \
  --coordinator http://192.168.56.10:8080 \
  --listen 0.0.0.0:9001 \
  --advertise-address 192.168.56.12 \
  --probe-interval 10s
```

---

## 7. Edge conductivity model for the prototype

For Phase 0, use a simplified version of the Physarum conductivity update.

For each directed edge `i -> j`:

```text
D_ij(t + Δt) = D_ij(t) + reinforcement - decay
```

Where:

```text
reinforcement = f(Q_ij) * (1 - D_ij)
decay         = r * D_ij
```

With:

```text
f(x) = x² / (1 + x²)
```

For the initial prototype:

```text
Q_ij = 1.0 if probe succeeds
Q_ij = 0.0 if probe fails
r    = 0.1
D_ij is clamped to [0.0, 1.0]
```

This means:

- successful probes reinforce the edge;
- failed or absent probes allow the edge to decay;
- `D_ij` never exceeds `1.0`;
- `D_ij` never drops below `0.0`.

---

## 8. Minimal test plan

### Test 1 — Server health

Start Server A:

```bash
physarum-server --listen 0.0.0.0:8080
```

Validate:

```bash
curl http://192.168.56.10:8080/health
```

Expected result:

```json
{
  "status": "ok"
}
```

### Test 2 — Agent registration

Start Agent B and Agent C.

Validate from any machine:

```bash
curl http://192.168.56.10:8080/agents
```

Expected result:

```json
[
  "agent-b",
  "agent-c"
]
```

### Test 3 — Peer discovery

Validate:

```bash
curl http://192.168.56.10:8080/peers/agent-b
```

Expected result:

```json
[
  "agent-c"
]
```

### Test 4 — Probe reporting

After both agents run for at least one interval, validate:

```bash
curl http://192.168.56.10:8080/graph
```

Expected result:

```text
agent-b -> agent-c exists
agent-c -> agent-b exists
D_ij > 0 for successful probes
```

### Test 5 — Decay behavior

Stop Agent C.

Wait several probe intervals.

Validate:

```bash
curl http://192.168.56.10:8080/graph
```

Expected result:

```text
agent-b -> agent-c starts decreasing over time
```

This proves that the graph is dynamic and not merely a static inventory.

---

## 9. Success criteria for Phase 0

Phase 0 is successful when:

- Server A starts reliably.
- Agent B registers successfully.
- Agent C registers successfully.
- B discovers C as a peer.
- C discovers B as a peer.
- B can probe C.
- C can probe B.
- Both agents report probe results to A.
- A exposes a graph containing B and C.
- The graph contains directed edges B -> C and C -> B.
- Edge conductivity increases after successful probes.
- Edge conductivity decays when probes fail or stop.

---

## 10. Phase 1 — Add path scoring

After Phase 0 works, add basic path scoring.

New server endpoint:

```text
GET /paths
```

For the A/B/C topology, this will be basic. The real value appears when adding a fourth node:

```text
A = Coordinator
B = External/perimeter-like agent
C = Gateway/application-like agent
D = Crown-jewel/database-like agent
```

Example path:

```text
B -> C -> D
```

The coordinator should calculate path attractiveness using:

```text
Attractiveness(path) = product(D_ij / L_ij)
```

For Phase 1, use:

```text
L_ij = 1.0
```

Later, `L_ij` can incorporate port exposure, vulnerability information, service weakness, and layer transition cost.

---

## 11. Phase 2 — Add security controls

After the graph loop is stable, add:

- Ed25519 signatures for reports.
- Agent enrollment tokens.
- Monotonic nonces.
- Replay protection.
- Coordinator certificate pinning.
- Optional mTLS.

The goal of Phase 2 is to prevent fake reports, replayed reports, and unauthorized agents from modifying the graph.

---

## 12. Phase 3 — Add eBPF telemetry

Only after the probe/report/graph loop works, add eBPF.

Initial eBPF goals:

- observe TCP connection state changes;
- count flows between local agent and peer IPs;
- export flow counts to user space;
- include observed flow signal in `Q_ij`.

At this point, update:

```text
Q_ij = w1 * Probe(i,j) + w2 * Observe(i,j)
```

Later, when validation agents exist:

```text
Q_ij = w1 * Probe(i,j) + w2 * Validation(i,j) + w3 * Observe(i,j)
```

---

## 13. Phase 4 — Add persistence and replay

Add persistence after the coordinator behavior is stable.

Recommended first options:

- SQLite for local prototype simplicity; or
- ClickHouse for time-series behavior closer to the final architecture.

Persist:

- agent registrations;
- probe reports;
- edge conductivity over time;
- graph snapshots;
- drift events.

Replay should allow reconstructing the graph from historical reports.

---

## 14. Phase 5 — Add TOON export and upstream integration

Once graph behavior is validated, add TOON export.

New endpoint:

```text
GET /toon/{target}
```

The output should include:

```text
source
target
ports
p_v
p_e
d_ij
q_ema
layer_emergent
layer_declared
data_completeness
```

This phase connects the prototype to the upstream autonomous validation and attack-path probability modeling system.

---

## 15. Recommended implementation order

Implement in this order:

```text
1. Create Rust workspace.
2. Create shared protocol crate.
3. Create server with /health.
4. Add /register.
5. Add /agents.
6. Create basic agent startup.
7. Make agent register with server.
8. Add /peers/{agent_id}.
9. Make agents fetch peers.
10. Add agent peer probe.
11. Add /report.
12. Store reports in server memory.
13. Build graph snapshot.
14. Add D_ij update.
15. Add decay loop.
16. Add /graph.
17. Test A/B/C lab.
18. Add path scoring.
19. Add signatures.
20. Add eBPF.
```

Do not start with eBPF. The first milestone is a working distributed graph loop.

---

## 16. Practical local deployment options

### Option A — Three local VMs

Best option for validating real network behavior.

Use:

- VirtualBox;
- VMware Fusion;
- Proxmox;
- Multipass;
- three small Linux VMs.

### Option B — Docker Compose

Best option for fast development.

Limitations:

- container networking may hide some real host behavior;
- not representative for eBPF host telemetry;
- still useful for validating API, registration, probes, and graph updates.

### Option C — One Linux host with three processes

Fastest option.

Use different ports for each process.

Example:

```text
server A: 127.0.0.1:8080
agent B:  127.0.0.1:9001
agent C:  127.0.0.1:9002
```

This is useful for development, but less realistic than separate VMs.

---

## 17. Prototype philosophy

The prototype should remain intentionally small.

The correct sequence is:

```text
Make it work.
Make it observable.
Make it correct.
Make it secure.
Make it fast.
Make it production-grade.
```

The first version should prove the living graph mechanism, not the final production architecture.

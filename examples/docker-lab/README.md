# Docker A/B/C/D Lab

Reproduces the four-process A/B/C/D prototype inside Docker Compose.

```
A  =  physarum-server   (coordinator, published on host port 8080)
B  =  agent-b           (perimeter-like / entry-layer,  probe port 9001 internal)
C  =  agent-c           (application/gateway-like,       probe port 9002 internal)
D  =  agent-d           (crown-jewel/database-like,      probe port 9003 internal)
```

All four containers share a Compose network. Agents B, C, and D discover
each other through the coordinator and probe each other using Docker service
names as addresses (`agent-b`, `agent-c`, `agent-d`). The current coordinator
returns all registered agents as peers (full mesh), so six directed edges form:

```
agent-b ↔ agent-c      (path-readiness: B → C)
agent-b ↔ agent-d
agent-c ↔ agent-d      (path-readiness: C → D)
```

The key path for future `/paths` endpoint validation:

```
agent-b → agent-c → agent-d
path_score = D_BC × D_CD ≈ 0.833 × 0.833 ≈ 0.694
```

---

## Prerequisites

- Docker Desktop ≥ 4.25 or Docker Engine ≥ 24 with Compose v2
- `curl` and `jq` on the host (for the validation script)

Verify:

```bash
docker compose version   # must be >= v2
```

---

## Step 1 — Build and start

Run from the repository root or from `examples/docker-lab/`:

```bash
# from the repository root
docker compose -f examples/docker-lab/docker-compose.yml up --build

# or from examples/docker-lab/
cd examples/docker-lab
docker compose up --build
```

The first build compiles the full Rust workspace and may take several minutes.
Subsequent builds reuse the Docker layer cache and are much faster.

Expected startup sequence:

```
physarum-server  | INFO physarum_server: physarum-server listening on 0.0.0.0:8080
agent-b          | INFO physarum_agent: probe server listening listen=0.0.0.0:9001 agent_id=agent-b
agent-b          | INFO physarum_agent: registered with coordinator agent_id=agent-b
agent-c          | INFO physarum_agent: probe server listening listen=0.0.0.0:9002 agent_id=agent-c
agent-c          | INFO physarum_agent: registered with coordinator agent_id=agent-c
agent-d          | INFO physarum_agent: probe server listening listen=0.0.0.0:9003 agent_id=agent-d
agent-d          | INFO physarum_agent: registered with coordinator agent_id=agent-d
```

All agents start only after the server passes its health check
(`GET /health` returns `"ok"`), so registration order is deterministic.

---

## Step 2 — Validate

Wait at least one probe interval (5 s) after all agents register, then run:

```bash
bash examples/docker-lab/check-docker-lab.sh
```

Expected output (34 checks — 1 health + 3 registration + 6 edges × 5 checks each):

```
[PASS] /health returns ok
[PASS] agent-b is registered
[PASS] agent-c is registered
[PASS] agent-d is registered
[PASS] edge agent-b -> agent-c exists
[PASS] edge agent-b -> agent-c probe_success=true
[PASS] edge agent-b -> agent-c d_ij > 0.0 (got 0.72)
[PASS] edge agent-b -> agent-c q_ema > 0.0 (got 0.91)
[PASS] edge agent-b -> agent-c sample_count > 0 (got 12)
[PASS] edge agent-c -> agent-b exists
[PASS] edge agent-c -> agent-b probe_success=true
[PASS] edge agent-c -> agent-b d_ij > 0.0 (got 0.72)
[PASS] edge agent-c -> agent-b q_ema > 0.0 (got 0.91)
[PASS] edge agent-c -> agent-b sample_count > 0 (got 12)
[PASS] edge agent-b -> agent-d exists
[PASS] edge agent-b -> agent-d probe_success=true
[PASS] edge agent-b -> agent-d d_ij > 0.0 (got 0.72)
[PASS] edge agent-b -> agent-d q_ema > 0.0 (got 0.91)
[PASS] edge agent-b -> agent-d sample_count > 0 (got 12)
[PASS] edge agent-d -> agent-b exists
[PASS] edge agent-d -> agent-b probe_success=true
[PASS] edge agent-d -> agent-b d_ij > 0.0 (got 0.72)
[PASS] edge agent-d -> agent-b q_ema > 0.0 (got 0.91)
[PASS] edge agent-d -> agent-b sample_count > 0 (got 12)
[PASS] edge agent-c -> agent-d exists
[PASS] edge agent-c -> agent-d probe_success=true
[PASS] edge agent-c -> agent-d d_ij > 0.0 (got 0.72)
[PASS] edge agent-c -> agent-d q_ema > 0.0 (got 0.91)
[PASS] edge agent-c -> agent-d sample_count > 0 (got 12)
[PASS] edge agent-d -> agent-c exists
[PASS] edge agent-d -> agent-c probe_success=true
[PASS] edge agent-d -> agent-c d_ij > 0.0 (got 0.72)
[PASS] edge agent-d -> agent-c q_ema > 0.0 (got 0.91)
[PASS] edge agent-d -> agent-c sample_count > 0 (got 12)

Results: 34 passed, 0 failed
```

The coordinator defaults to `http://127.0.0.1:8080`. Override with:

```bash
PHYSARUM_COORDINATOR=http://127.0.0.1:8080 bash examples/docker-lab/check-docker-lab.sh
```

---

## Step 3 — Inspect manually

```bash
# Health
curl -s http://127.0.0.1:8080/health | jq

# Registered agents (should list agent-b, agent-c, agent-d)
curl -s http://127.0.0.1:8080/agents | jq

# Peers of agent-b (should list agent-c and agent-d)
curl -s http://127.0.0.1:8080/peers/agent-b | jq

# Full graph with conductivity (six directed edges)
curl -s http://127.0.0.1:8080/graph | jq
```

---

## Step 4 — Stop

```bash
# Stop and remove containers (keeps the built image)
docker compose down

# Stop and remove containers + image + volumes
docker compose down --rmi local --volumes
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Any agent exits immediately | Server not healthy yet | `depends_on` health check handles this; check server logs |
| `connection refused` on port 8080 | Server container not running | Run `docker compose ps` to check status |
| `d_ij` stays at `0.0` | No probe interval has elapsed yet | Wait ≥ 5 s after all agents register |
| Missing edges in `/graph` | One agent failed to start | Check `docker compose logs agent-b` / `agent-c` / `agent-d` |
| `address already in use` on 8080 | Port conflict with another process | Stop the conflicting process or change the host port in `docker-compose.yml` |
| Build fails on `libssl-dev` | Docker networking issue during build | Retry `docker compose build`; check internet connectivity |
| `jq` not found | Not installed on host | `brew install jq` / `apt install jq` |

---

## Next topology: A/B/C/D lab

The current Docker lab proves the A/B/C case (one adaptive edge pair). The planned next step is to extend to four agents.

### A/B/C/D agent roles

```
A  =  physarum-server   (coordinator)
B  =  agent-b           (perimeter-like / entry-layer)
C  =  agent-c           (application/gateway-like)
D  =  agent-d           (crown-jewel/database-like)
```

### Docker service names (A/B/C/D)

```text
physarum-server
agent-b
agent-c
agent-d
```

### Why agent D matters

```text
B ↔ C  — one adaptive edge pair (current lab)
B → C → D  — first meaningful attack path (next lab)
```

The key transition:

```text
adaptive edge: D_BC
adaptive path: D_BC × D_CD  (path score ≈ 0.694 at equilibrium)
```

### Expected A/B/C/D graph

With all three agents running, the coordinator currently returns all registered agents as peers (full mesh). Expected edges:

```text
agent-b -> agent-c      (path-readiness edge)
agent-c -> agent-b
agent-b -> agent-d
agent-d -> agent-b
agent-c -> agent-d      (path-readiness edge)
agent-d -> agent-c
```

### Expected A/B/C/D validation checks

```text
agent-b registered
agent-c registered
agent-d registered
/graph nodes include agent-b, agent-c, agent-d
agent-b -> agent-c: probe_success=true, q_ema>0.0, d_ij>0.0, sample_count>0
agent-c -> agent-d: probe_success=true, q_ema>0.0, d_ij>0.0, sample_count>0
(all six full-mesh edges also validated if full mesh is active)
```

### Adaptive path scoring

Query all simple paths from `agent-b` to `agent-d`, sorted by score = product(d\_ij):

```bash
curl -s 'http://127.0.0.1:8080/paths?source=agent-b&target=agent-d' | jq
```

Because the A/B/C/D lab is full-mesh, the response will include both the direct
hop and the two-hop path. The order depends on live conductivity values — the
direct `agent-b → agent-d` edge may outscore the two-hop route if its `d_ij`
is higher. Path ranking reflects live conductivity, not hop count.

Example response shape (actual scores vary with live d\_ij values):

```json
{
  "source": "agent-b",
  "target": "agent-d",
  "paths": [
    {
      "nodes": ["agent-b", "agent-d"],
      "edges": [{ "source": "agent-b", "target": "agent-d", "d_ij": 0.833, "q_ema": 0.91 }],
      "score": 0.833
    },
    {
      "nodes": ["agent-b", "agent-c", "agent-d"],
      "edges": [
        { "source": "agent-b", "target": "agent-c", "d_ij": 0.833, "q_ema": 0.91 },
        { "source": "agent-c", "target": "agent-d", "d_ij": 0.833, "q_ema": 0.91 }
      ],
      "score": 0.694
    }
  ]
}

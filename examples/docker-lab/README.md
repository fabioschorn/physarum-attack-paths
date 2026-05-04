# Docker A/B/C Lab

Reproduces the minimal three-process A/B/C prototype inside Docker Compose.

```
A  =  physarum-server   (coordinator, published on host port 8080)
B  =  physarum-agent    (agent-b, probe port 9001 internal)
C  =  physarum-agent    (agent-c, probe port 9002 internal)
```

All three containers share a Compose network. Agent B and agent C discover
each other through the coordinator and probe each other using Docker service
names as addresses (`agent-b`, `agent-c`).

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
```

`agent-b` and `agent-c` only start after the server passes its health check
(`GET /health` returns `"ok"`), so registration order is deterministic.

---

## Step 2 — Validate

Wait at least one probe interval (5 s) after both agents are running, then run:

```bash
bash examples/docker-lab/check-docker-lab.sh
```

Expected output:

```
[PASS] /health returns ok
[PASS] agent-b is registered
[PASS] agent-c is registered
[PASS] /peers/agent-b contains agent-c
[PASS] /peers/agent-b excludes agent-b itself
[PASS] edge agent-b -> agent-c exists
[PASS] edge agent-c -> agent-b exists
[PASS] edge agent-b -> agent-c probe_success=true
[PASS] edge agent-c -> agent-b probe_success=true
[PASS] edge agent-b -> agent-c d_ij > 0.0
[PASS] edge agent-c -> agent-b d_ij > 0.0
[PASS] edge agent-b -> agent-c q_ema > 0.0
[PASS] edge agent-c -> agent-b q_ema > 0.0
[PASS] edge agent-b -> agent-c sample_count > 0
[PASS] edge agent-c -> agent-b sample_count > 0

Results: 15 passed, 0 failed
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

# Registered agents
curl -s http://127.0.0.1:8080/agents | jq

# Peers of agent-b
curl -s http://127.0.0.1:8080/peers/agent-b | jq

# Full graph with conductivity
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
| `agent-b` / `agent-c` exit immediately | Server not healthy yet | `depends_on` health check handles this; check server logs |
| `connection refused` on port 8080 | Server container not running | Run `docker compose ps` to check status |
| `d_ij` stays at `0.0` | No probe interval has elapsed yet | Wait ≥ 5 s after both agents register |
| Only one edge in `/graph` | One agent failed to start | Check `docker compose logs agent-b` / `agent-c` |
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

### Future /paths readiness

Once Issue #17 implements the `/paths` endpoint, the path can be queried:

```bash
curl -s 'http://127.0.0.1:8080/paths?source=agent-b&target=agent-d' | jq
```

Expected conceptual response:

```json
{
  "source": "agent-b",
  "target": "agent-d",
  "paths": [
    {
      "nodes": ["agent-b", "agent-c", "agent-d"],
      "score": 0.694
    }
  ]
}
```

The Docker A/B/C/D lab implementation is tracked in Issue #16.

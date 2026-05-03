# Local A/B/C Lab

Reproduces the minimal three-process prototype on a single machine:

```
A  =  physarum-server   (coordinator, port 8080)
B  =  physarum-agent    (agent-b, probe port 9001)
C  =  physarum-agent    (agent-c, probe port 9002)
```

Each agent discovers the other through the coordinator, probes it over
HTTP, and reports success/RTT back. The coordinator accumulates directed
edges and updates the Physarum conductivity value `D_ij` for each one.

---

## Prerequisites

- Rust toolchain ≥ 1.78 (`rustup show`)
- `jq` for JSON formatting (`brew install jq` / `apt install jq`)
- Four terminal windows (or tmux panes)

---

## Step 1 — Start the coordinator (Terminal 1)

```bash
cargo run -p physarum-server -- --listen 127.0.0.1:8080
```

Expected first log line:

```
INFO physarum_server: physarum-server listening on 127.0.0.1:8080
```

---

## Step 2 — Start agent B (Terminal 2)

```bash
cargo run -p physarum-agent -- \
  --id agent-b \
  --coordinator http://127.0.0.1:8080 \
  --listen 127.0.0.1:9001 \
  --advertise-address 127.0.0.1 \
  --probe-interval-seconds 5
```

Expected log lines:

```
INFO physarum_agent: probe server listening listen=127.0.0.1:9001 agent_id=agent-b
INFO physarum_agent: registered with coordinator agent_id=agent-b coordinator=http://127.0.0.1:8080
```

---

## Step 3 — Start agent C (Terminal 3)

```bash
cargo run -p physarum-agent -- \
  --id agent-c \
  --coordinator http://127.0.0.1:8080 \
  --listen 127.0.0.1:9002 \
  --advertise-address 127.0.0.1 \
  --probe-interval-seconds 5
```

---

## Step 4 — Validate (Terminal 4)

Wait at least one probe interval (5 s) after both agents are running,
then run the commands below.

### Health check

```bash
curl -s http://127.0.0.1:8080/health | jq
```

Expected:

```json
"ok"
```

### Registered agents

```bash
curl -s http://127.0.0.1:8080/agents | jq
```

Expected (order may vary):

```json
[
  {
    "agent_id": "agent-b",
    "address": "127.0.0.1",
    "probe_port": 9001,
    "last_seen": "<timestamp>"
  },
  {
    "agent_id": "agent-c",
    "address": "127.0.0.1",
    "probe_port": 9002,
    "last_seen": "<timestamp>"
  }
]
```

### Peers of agent-b

```bash
curl -s http://127.0.0.1:8080/peers/agent-b | jq
```

Expected: only `agent-c` is returned (the agent excludes itself).

```json
[
  {
    "agent_id": "agent-c",
    "address": "127.0.0.1",
    "probe_port": 9002
  }
]
```

### Graph (directed edges + conductivity)

```bash
curl -s http://127.0.0.1:8080/graph | jq
```

Expected after several probe intervals:

```json
{
  "nodes": ["agent-b", "agent-c"],
  "edges": [
    {
      "source": "agent-b",
      "target": "agent-c",
      "probe_success": true,
      "d_ij": 0.8327872000000001,
      "last_seen": "<timestamp>"
    },
    {
      "source": "agent-c",
      "target": "agent-b",
      "probe_success": true,
      "d_ij": 0.8327872000000001,
      "last_seen": "<timestamp>"
    }
  ]
}
```

Both directed edges must be present with `probe_success: true` and `d_ij > 0.0`.

---

## D_ij convergence

The Physarum conductivity model used here is:

```
D_ij(t+1) = D_ij(t) + f(Q) · (1 − D_ij) − r · D_ij
```

where `f(Q) = Q² / (1 + Q²)` and `r = 0.1` (decay rate).

For a successful probe `Q = 1`, so `f(1) = 0.5`. The stable equilibrium
under continuous successful probes is:

```
D* = f(1) / (f(1) + r) = 0.5 / (0.5 + 0.1) = 5/6 ≈ 0.8333
```

After enough intervals `D_ij` converges to approximately `0.833` but
never reaches `1.0`. A single failure immediately pulls it down by
`r · D_ij`.

---

## Validation script

`check-local-lab.sh` automates the checks above.
Run it after all three processes are up and at least one probe interval
has elapsed:

```bash
bash examples/local-lab/check-local-lab.sh
```

The script exits `0` on success and `1` on any failed assertion.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `connection refused` on `/register` | Server not started yet | Start Terminal 1 first |
| `D_ij` stays at `0.0` | No probe interval has elapsed | Wait ≥ `--probe-interval-seconds` |
| Only one edge in `/graph` | One agent started but not the other | Start both agents |
| `address already in use` on 9001/9002 | Previous run still running | Kill old processes |
| `jq` not found | Not installed | `brew install jq` / `apt install jq` |

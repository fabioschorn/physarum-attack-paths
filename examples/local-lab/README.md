# Local A/B/C Lab

Reproduces the minimal three-process prototype on a single machine:

```
A  =  physarum-server   (coordinator, port 8080)
B  =  physarum-agent    (agent-b, probe port 9001)
C  =  physarum-agent    (agent-c, probe port 9002)
```

Each agent maintains a short-term observation window per peer and sends
an enriched `ProbeReport` that includes `success_rate`, `avg_rtt_ms`,
and `jitter_ms`. The coordinator turns those reports into a normalised
stimulus signal `Q_ij`, smooths it with an exponential moving average
(`q_ema`), and drives the Physarum conductivity `D_ij` with that signal
instead of reacting to a raw boolean.

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
      "d_ij": 0.72,
      "q_ema": 0.91,
      "success_rate": 1.0,
      "avg_rtt_ms": 0.0,
      "jitter_ms": 0.0,
      "sample_count": 12,
      "last_seen": "<timestamp>"
    },
    {
      "source": "agent-c",
      "target": "agent-b",
      "probe_success": true,
      "d_ij": 0.72,
      "q_ema": 0.91,
      "success_rate": 1.0,
      "avg_rtt_ms": 0.0,
      "jitter_ms": 0.0,
      "sample_count": 12,
      "last_seen": "<timestamp>"
    }
  ]
}
```

Both directed edges must be present with `probe_success: true`,
`d_ij > 0.0`, and `q_ema > 0.0`.

---

## Stimulus-oriented model and D_ij convergence

The system now flows through three stages:

```
local observation window  →  enriched ProbeReport  →  Q_ij  →  q_ema  →  D_ij
```

### Stage 1 — local observation window (agent)

Each agent keeps a bounded per-peer sliding window of the last 20 probe
samples. Each sample records whether the probe succeeded and an RTT when
available. The agent computes `success_rate`, `sample_count`, `avg_rtt_ms`,
and `jitter_ms` from that recent window only — old samples are evicted as new
ones arrive. Every `ProbeReport` includes these summaries:

| Field | Meaning |
|---|---|
| `success_rate` | fraction of recent probes that succeeded |
| `avg_rtt_ms` | mean RTT of successful probes |
| `jitter_ms` | mean absolute deviation of RTT |
| `sample_count` | total probes in the window |

### Stage 2 — stimulus Q_ij (coordinator)

The coordinator converts each enriched report into a normalised stimulus:

```
latency_score = 1 / (1 + avg_rtt_ms / 100)
Q_ij = clamp(0.7 · success_rate + 0.3 · latency_score, 0.0, 1.0)
```

If `success_rate = 0.0`, Q_ij is set to 0.0 (latency is undefined when
all probes fail).

### Stage 3 — q_ema and D_ij (coordinator)

`q_ema` smooths Q_ij with an exponential moving average (α = 0.3):

```
q_ema(t+1) = 0.3 · Q_ij + 0.7 · q_ema(t)
```

Then `q_ema` drives the Physarum conductivity update:

```
D_ij(t+1) = D_ij(t) + f(q_ema) · (1 − D_ij) − r · D_ij
```

where `f(x) = x² / (1 + x²)` and `r = 0.1`.

For a fast, always-reachable peer (success_rate=1.0, avg_rtt_ms≈0),
`Q_ij ≈ 1.0` and `q_ema → 1.0`. The stable equilibrium is:

```
D* = f(1) / (f(1) + r) = 0.5 / 0.6 = 5/6 ≈ 0.833
```

Under sustained failure (`success_rate = 0.0`), `Q_ij = 0`, `q_ema → 0`,
and D_ij decays to zero via the `r · D_ij` term.

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

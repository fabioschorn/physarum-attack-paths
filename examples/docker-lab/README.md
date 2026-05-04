# Docker Lab — Local Reproducible A/B/C Testing

This document defines the intended Docker-based local laboratory for `physarum-attack-paths`.

The Docker lab is meant to complement the existing `examples/local-lab` runbook. The local lab is useful for manual execution in multiple terminals. The Docker lab should make the same scenario easier to reproduce with a single command.

---

## 1. Purpose

The purpose of the Docker lab is to provide a fast, repeatable development environment for the current A/B/C prototype:

```text
A = physarum-server
B = physarum-agent
C = physarum-agent
```

The lab should validate that:

```text
agent-b registers with the coordinator
agent-c registers with the coordinator
agent-b discovers agent-c
agent-c discovers agent-b
both agents probe each other
both agents send enriched ProbeReport messages
server computes Q_ij
server updates q_ema
server updates D_ij
/graph exposes the adaptive edge state
```

This lab is not intended to represent production-grade network segmentation. It is primarily a developer productivity tool.

---

## 2. Why Docker before AWS

Docker is useful because it is:

```text
cheap
fast
reproducible
simple to reset
suitable for CI-like local checks
```

AWS is more realistic for network behavior, but it introduces additional complexity:

```text
VPC
subnets
security groups
routing
IAM
EC2 lifecycle
cost management
Terraform state
```

Therefore, the recommended sequence is:

```text
1. Keep examples/local-lab for manual process testing.
2. Add examples/docker-lab for repeatable containerized A/B/C testing.
3. Add examples/aws-lab documentation for future real-network testing.
4. Implement AWS infrastructure only after the Docker lab and A/B/C/D design are stable.
```

---

## 3. Target topology

The Docker Compose topology should start three services:

```text
physarum-server
physarum-agent-b
physarum-agent-c
```

Logical topology:

```text
                 ┌────────────────────────┐
                 │ physarum-server         │
                 │ 0.0.0.0:8080            │
                 └───────────┬────────────┘
                             ▲
                reports      │      reports
                             │
        ┌────────────────────┴────────────────────┐
        │                                         │
        ▼                                         ▼
┌───────────────────┐                   ┌───────────────────┐
│ physarum-agent-b   │◄────────────────►│ physarum-agent-c   │
│ probe port 9001    │                   │ probe port 9002    │
└───────────────────┘                   └───────────────────┘
```

Suggested Docker network:

```text
physarum-lab-net
```

Suggested service DNS names:

```text
physarum-server
agent-b
agent-c
```

---

## 4. Expected service commands

The server container should run something equivalent to:

```bash
physarum-server --listen 0.0.0.0:8080
```

Agent B should run something equivalent to:

```bash
physarum-agent \
  --id agent-b \
  --coordinator http://physarum-server:8080 \
  --listen 0.0.0.0:9001 \
  --advertise-address agent-b \
  --probe-interval-seconds 5
```

Agent C should run something equivalent to:

```bash
physarum-agent \
  --id agent-c \
  --coordinator http://physarum-server:8080 \
  --listen 0.0.0.0:9002 \
  --advertise-address agent-c \
  --probe-interval-seconds 5
```

The important point is that `advertise-address` should be resolvable by the other containers. In Docker Compose, the service name is usually the cleanest option.

---

## 5. Required files to implement later

The intended implementation should add:

```text
examples/docker-lab/docker-compose.yml
examples/docker-lab/check-docker-lab.sh
```

Optionally:

```text
examples/docker-lab/.env.example
examples/docker-lab/Dockerfile
```

The implementation may reuse the workspace build directly or create a small multi-stage Dockerfile. Keep it simple at first.

---

## 6. Expected usage

Target developer workflow:

```bash
cd examples/docker-lab
docker compose up --build
```

Then, from another terminal:

```bash
bash examples/docker-lab/check-docker-lab.sh
```

Or directly:

```bash
curl -s http://127.0.0.1:8080/health | jq
curl -s http://127.0.0.1:8080/agents | jq
curl -s http://127.0.0.1:8080/peers/agent-b | jq
curl -s http://127.0.0.1:8080/graph | jq
```

---

## 7. Expected graph output

After both agents have run for at least one probe interval, `/graph` should show two nodes and two directed edges:

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
      "q_ema": 0.91,
      "success_rate": 1.0,
      "avg_rtt_ms": 1.0,
      "jitter_ms": 0.0,
      "sample_count": 5,
      "last_seen": "<timestamp>"
    },
    {
      "source": "agent-c",
      "target": "agent-b",
      "probe_success": true,
      "d_ij": 0.72,
      "q_ema": 0.91,
      "success_rate": 1.0,
      "avg_rtt_ms": 1.0,
      "jitter_ms": 0.0,
      "sample_count": 5,
      "last_seen": "<timestamp>"
    }
  ]
}
```

The exact values are not required to match. The required properties are:

```text
agent-b exists
agent-c exists
agent-b -> agent-c exists
agent-c -> agent-b exists
probe_success is true for both edges
q_ema > 0.0 for both edges
d_ij > 0.0 for both edges
sample_count > 0 for both edges
```

---

## 8. Validation script expectations

`check-docker-lab.sh` should validate:

```text
/health returns ok
/agents contains agent-b
/agents contains agent-c
/peers/agent-b contains agent-c
/peers/agent-b excludes agent-b
/graph contains agent-b -> agent-c
/graph contains agent-c -> agent-b
both edges have probe_success == true
both edges have q_ema > 0.0
both edges have d_ij > 0.0
both edges have sample_count > 0
```

Use simple tools:

```text
bash
curl
jq
awk
```

---

## 9. Out of scope for Docker lab

Do not add these in the first Docker lab implementation:

```text
Agent D
/paths
path scoring
MCPM-inspired traversal
AWS infrastructure
Terraform
Kubernetes
Helm
mTLS
Ed25519 signatures
persistence
eBPF
TOON export
```

The Docker lab should remain a simple A/B/C reproducibility layer.

---

## 10. Relationship to other labs

```text
examples/local-lab
  Manual runbook using local host processes and multiple terminals.

examples/docker-lab
  Reproducible containerized A/B/C lab for developer convenience.

examples/aws-lab
  Future realistic EC2/VPC/subnet/security-group validation plan.
```

Docker is for speed. AWS is for realism.

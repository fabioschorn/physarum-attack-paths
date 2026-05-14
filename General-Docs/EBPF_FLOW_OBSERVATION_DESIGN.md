# eBPF Passive Flow Observation — Design and Test Strategy

**Status:** Stage 0 design merged (PR #62); Stage 1 / Gate I implemented (PR #68); Stage 2–3 / Gate J implemented and AWS EC2 validated (Issue #69, PR #71)  
**Issue:** #61  
**Author:** Dev Lead  
**Date:** 2026-05-10

---

## Summary

Active probes tell us which paths _can_ be reached.  
eBPF flow observation tells us which paths are _actually being used_.

```text
probes       = active reachability evidence
eBPF         = passive observed-flow evidence
D_ij / q_ema = adaptive graph memory that combines both
```

This document defines the architecture, security boundaries, data model, and test strategy for the first eBPF prototype. No eBPF code is implemented here — Stage 0 is the design agreement only.

---

## Design decisions

### 1. Collection approach — Option B: sidecar observer

**Decision:** `physarum-ebpf-observer` — a separate binary running alongside the existing agent, not embedded inside it.

**Rationale:**

- Keeps the stable `physarum-agent` untouched during the eBPF experiment.
- The observer can be toggled, restarted, or replaced without touching agent behaviour.
- eBPF programs require elevated privileges (`CAP_BPF`, `CAP_PERFMON`) — isolating this capability to a separate binary limits the privilege surface.
- Clean separation of concerns: agent owns probing and scoring; observer owns passive visibility.

**Not chosen:**
- Option A (embedded): would require privilege changes to the main agent binary prematurely.
- Option C (central): VPC Flow Logs are delayed and coarse; host eBPF is the intended signal for this project.

---

### 2. Rust/eBPF stack — Aya (aya-rs)

**Decision:** [Aya](https://github.com/aya-rs/aya) as the production implementation stack.

**Rationale:**

- Pure Rust — no C dependencies or `libbpf` linkage required.
- CO-RE (Compile Once, Run Everywhere) via BTF relocations: program compiled once, runs on different kernel versions without recompilation.
- Amazon Linux 2023 ships a BTF-enabled kernel (6.1.x series). Aya is validated against this kernel family.
- Consistent with the Rust-centric workspace; no Python/C build tooling introduced.
- Aya supports the tracepoint and kprobe program types needed for TCP connect/accept.

**Build note:** Aya requires a separate BPF compilation target (`bpfel-unknown-none`) for the eBPF bytecode, linked with `bpf-linker`. The eBPF program code lives in a dedicated crate (`physarum-ebpf-observer-ebpf`); the userspace controller is a normal Rust binary. This is the standard Aya workspace layout.

**Acceptable for research only:** `bpftrace` one-liners to validate hook selection before writing Aya code. Must not be merged as the primary implementation.

---

### 3. Event source — `sock/inet_sock_set_state` tracepoint

**Decision:** Use the `tracepoint/sock/inet_sock_set_state` tracepoint as the primary hook for v1.

**Rationale:**

This tracepoint fires on every TCP state transition. Filtering for `TCP_ESTABLISHED` (connect success / accept) and `TCP_CLOSE` (connection end) gives us:

- Outbound connects: `oldstate=TCP_SYN_SENT, newstate=TCP_ESTABLISHED`
- Inbound accepts: `oldstate=TCP_SYN_RECV, newstate=TCP_ESTABLISHED`
- Connection close: `newstate=TCP_CLOSE`

One hook captures both inbound and outbound flows without separate `connect` / `accept` probes. It is a stable tracepoint (not a kprobe), which reduces sensitivity to kernel version differences.

**Not chosen for v1:**
- `tracepoint/syscalls/sys_enter_connect` + exit: syscall-level, only catches outbound; requires correlating entry/exit for return code.
- `kprobe/tcp_v4_connect`: kprobe (unstable ABI across kernel versions); no BTF guarantee.
- XDP/TC packet-level hooks: far more complex, closer to packet capture, out of scope for v1.

**Fields available from `inet_sock_set_state`:**

```c
u64  skaddr        // socket pointer (used only as key, never exposed)
int  oldstate
int  newstate
u16  sport         // source port
u16  dport         // destination port
u16  family        // AF_INET or AF_INET6
u16  protocol
u8   saddr[4]      // source IPv4
u8   daddr[4]      // destination IPv4
```

PID and process name (`comm`) are read from the current task context (`bpf_get_current_pid_tgid` / `bpf_get_current_comm`).

**Tracepoint format validation (Stage 2/3 requirement):** Before relying on the field layout above, capture and document the actual format on the target AL2023 kernel:

```bash
sudo cat /sys/kernel/tracing/events/sock/inet_sock_set_state/format
```

Record the kernel version and tracepoint format as a short evidence block in the Stage 2/3 validation evidence file. Do not commit the full raw output unless fields diverge from what is listed here.

---

### 4. Exact metadata collected

```json
{
  "agent_id": "agent-b",
  "observed_at": "2026-05-10T00:00:00.000000000Z",
  "source_ip": "10.50.20.10",
  "source_port": 53124,
  "destination_ip": "10.50.30.10",
  "destination_port": 9002,
  "protocol": "tcp",
  "direction": "outbound",
  "event": "connect_established",
  "pid": 1234,
  "comm": "physarum-agent"
}
```

`event` values: `connect_established`, `accept_established`, `close`.  
`direction` is derived from event type: outbound for connect, inbound for accept.  
`agent_id` is configured on the observer at startup (not read from the kernel).

---

### 5. Explicitly excluded — non-negotiable

```text
Payload capture                     — never
Socket buffer contents              — never
HTTP request/response bodies        — never
TLS handshake data                  — never
Any data after the TCP header       — never
Environment variables               — never
File descriptor contents            — never
Raw pcap / pcap-ng output           — never
AWS credentials or tokens           — never
Private keys or certificates        — never
Process memory or arguments         — never (comm = process name only, max 15 chars)
```

Any eBPF program that reads beyond TCP metadata must be rejected in review.

Evidence files: public IPs must be redacted before commit (`<redacted>`). Private/internal IPs within lab CIDR are acceptable.

---

### 6. Scoring integration — Stage 1: separate collection only

**Decision:** Flow observations are collected and exposed through a dedicated endpoint. They do not affect `D_ij` or `q_ema` in Stage 1.

**Rationale:**

The signal quality and reliability of passive eBPF flows is unvalidated. We need to observe the data in production conditions (AWS EC2) before assuming it is a reliable input to scoring. Premature integration risks instability in the scoring model.

**Stage 1:** `POST /flow-observations` ingests events. `GET /flow-observations` exposes them. Scoring unchanged.  
**Stage 4 / future gate:** After passive evidence is validated and reliable (Stages 2–3), define a reinforcement formula that combines active probe quality and observed flow frequency into `D_ij` / `q_ema`.

---

### 7. Smallest safe test that proves value

**One test:** On a Linux machine with eBPF support, start `physarum-ebpf-observer` configured for `agent-b`. Then run `curl` or any TCP client from the same host to connect to a known IP:port. Assert that the observer emits exactly one `connect_established` event with the correct `source_ip`, `destination_ip`, `destination_port`, and `comm`. No payload in the event. This proves the eBPF hook fires, metadata is captured, and the event is serialized correctly.

---

### 8. First runtime test environment — AWS EC2, not Docker

**Decision:** Target AWS EC2 (Amazon Linux 2023) as the first integration runtime. Docker eBPF is not a blocker.

**Rationale:**

- AL2023 EC2 instances have a BTF-enabled kernel with `CAP_BPF` and `CAP_PERFMON` available to processes running as root.
- Docker eBPF requires privileged containers and is host-kernel dependent; macOS Docker Desktop does not support eBPF at all.
- The existing AWS lab Terraform already provisions AL2023 nodes — the observer can be added to the `agent.sh` bootstrap without new infrastructure.

Docker Layer 3 in the test strategy is listed as _optional_ — skip to AWS EC2 if Docker eBPF is unreliable.

---

### 9. Files, crates, and endpoints to add

**Stage 0 — this document (Issue #61):**

```text
General-Docs/EBPF_FLOW_OBSERVATION_DESIGN.md    ← this file
```

**Stage 1 — server scaffolding (separate PR):**

```text
crates/physarum-protocol/src/flow_observation.rs
    FlowObservation struct, Direction enum, EventType enum
    Serde + JSON

crates/physarum-server/src/routes/flow_observations.rs
    POST /flow-observations    (ingests FlowObservation, stores in-memory ring buffer)
    GET  /flow-observations    (returns recent N events)

crates/physarum-server/tests/flow_observations.rs
    Unit/integration tests for endpoint; no eBPF required
```

Cargo.toml workspace: keep `crates/physarum-ebpf` commented until Stage 2.

**Stage 2 — observer crate (separate PR):**

```text
crates/physarum-ebpf-observer/
    Cargo.toml
    src/main.rs           (userspace controller: loads BPF program, posts to server)
    src/config.rs         (agent_id, server_url, filter_ports)

crates/physarum-ebpf-observer-ebpf/
    Cargo.toml            (BPF target: bpfel-unknown-none)
    src/main.rs           (eBPF program: tcp state tracepoint)

xtask/src/build_ebpf.rs  (build helper to compile BPF target)
```

Rename `crates/physarum-ebpf` → `crates/physarum-ebpf-observer` (matches binary name). Uncomment in workspace Cargo.toml.

AWS lab: add observer bootstrap to `agent.sh` when `enable_ebpf_observer=true` (Terraform variable, default false).

---

### 10. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| BTF not available on target kernel | Low — AL2023 ships BTF | Verify `ls /sys/kernel/btf/vmlinux` at bootstrap; fail fast |
| `bpf-linker` / BPF toolchain build complexity in CI | Medium | CI needs privileged Linux runner; keep eBPF crate gated behind feature or separate job |
| macOS dev cannot run eBPF integration tests | Certain | Unit tests only on Mac; integration tests require Linux runner or EC2 SSH |
| Observer drops events under high throughput | Low for lab scale | Use a BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`) as the preferred prototype transport; expose dropped-event counters in observer logs so losses are visible |
| Port → agent-id mapping requires configuration | Medium | Observer is configured with `--listen-ports` at startup; coordinator must expose port registry in future |
| Accidental payload capture in a future eBPF program | Low but high impact | Mandatory review rule: no reads from `skb` data pointers; BPF verifier rejects most payload reads anyway |
| Signal latency — eBPF events arrive after scoring | Medium | Stage 1 collects separately; scoring integration is Stage 2 after signal reliability is confirmed |
| Docker eBPF unreliability | High | Not blocking — skip Docker Layer 3; go to EC2 |

---

## Security boundary summary

```text
COLLECT    timestamp, src/dst IP, src/dst port, protocol, event, pid, comm (15 chars)
DO NOT     read packet payload, socket buffers, process environment, credentials
REDACT     public IPs in evidence files before commit
PRIVILEGE  Prefer least privilege with CAP_BPF + CAP_PERFMON where supported; first AWS
           prototype may run as root/systemd while we verify AL2023 requirements. Do not
           assume CAP_SYS_ADMIN is never required until validated on the target kernel.
           Record exact privileges used on EC2 in Stage 2/3 evidence.
BINARY     observer is a separate binary; physarum-agent unchanged
TELEMETRY  Flow observations are telemetry, not authorization truth. They must not be used
           to infer permission or access control guarantees without corroborating active
           probes or policy evidence.
```

---

## Test strategy

| Layer | Environment | eBPF required | What is validated |
|---|---|---|---|
| 1 — unit | Any (Mac/Linux) | No | FlowObservation serde, POST/GET endpoints, sanitization, mapping logic |
| 2 — Linux integration | Linux dev VM or CI | Yes | Observer sees TCP connect from test process; metadata only; no payload |
| 3 — Docker (optional) | Privileged Linux container | Yes (if kernel supports) | Observer sees inter-container TCP flows; skip if unreliable |
| 4 — AWS EC2 | EC2 AL2023 instances | Yes | Observer runs on EC2 agents; sees agent-to-agent TCP flows; reports to server; resources destroyed |

Layer 4 is the gate exit criterion for Stage 2.

---

## Out of scope

```text
Payload capture                 — never in this project
XDP / TC packet hooks           — not in v1
Production daemon hardening     — deferred
mTLS between observer and server — deferred
Scoring changes (D_ij / q_ema) — Stage 2 only
Large topology (>5 agents)      — deferred
Cloud-wide flow log ingestion   — out of scope
Kernel bypass optimization      — out of scope
IPv6 flows                      — v1 is IPv4 only
```

---

## Future direction — controlled Physarum-inspired expansion

The long-term direction is to model agents as computational analogues of Physarum polycephalum. In controlled environments, agents may eventually use eBPF flow evidence and RustScan-based service discovery to identify candidate next steps, expand through the environment, reinforce productive paths, and decay weaker or unproductive paths.

This future work remains intentionally separate from the Stage 0 eBPF design. PR #62 defines the passive flow observation foundation. RustScan integration, agent replication, and controlled expansion will be defined in future gates.

The intended sequence:

```text
1. eBPF passive flow observation first.
2. RustScan later as a library available to agents for service discovery.
3. Controlled Physarum-inspired expansion/replication in future gates.
```

---

## Stage sequence and gate mapping

| Stage | Deliverable | Gate |
|---|---|---|
| 0 | This design document | Issue #61 |
| 1 | FlowObservation model + POST/GET /flow-observations + unit tests | Gate I — COMPLETED (PR #68) |
| 2 | physarum-ebpf-observer crate; TCP state tracepoint; posts to server | Gate J — COMPLETED (PR #71) |
| 3 | AWS EC2 validation — observer sees agent flows; evidence file | Gate J exit — COMPLETED (Issue #69) |
| 4 | Scoring integration proposal (combine probes + flows) | Gate K |

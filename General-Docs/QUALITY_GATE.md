# Quality Gate — Physarum Attack Paths

**Current gate:** PF-2 — Adaptive Re-routing — COMPLETE  
**Overall status:** GREEN (Adaptive Path Prototype) · GREEN (AWS Mode 1 Runtime) · GREEN (AWS Phase Identity) · GREEN (AWS Mode 2 Runtime) · GREEN (B/C/D TLA+ Path-Selection Model) · GREEN (Weighted Competing Paths) · GREEN (AWS tc/netem Weighted Paths) · GREEN (FlowObservation Model and Server Endpoints) · GREEN (eBPF Observer Runtime) · GREEN (eBPF Observer Agent Flow Correlation) · GREEN (Gate K) · GREEN (Gate K.1) · GREEN (Gate L) · GREEN (Gate L.1) · GREEN (Gate L.2) · GREEN (Gate L.3) · GREEN (Gate M) · GREEN (Gate M.4) · GREEN (PF-1) · GREEN (PF-2)  
**Last updated:** 2026-05-25

> GREEN = ready to advance · YELLOW = usable, follow-up required · RED = blocked or unstable · FUTURE = planned, not blocking current gate

---

## Gate checklist

| Area | Status | Evidence | Notes |
|---|---|---|---|
| Build / test health | GREEN | 86 tests passing | `cargo test --workspace` — 18 agent + 16 observer + 12 protocol + 40 server; last verified PR #82 |
| Gate K.1 — autonomous path selection (negative-log scoring + selected_path + secondary_conduits) | GREEN | `autonomous-path-selection-evidence.txt` | Issue #80 / PR #82 |
| Gate L — physarum-scanner crate (RustScan feature parity, rlimit, LCG port ordering) | GREEN | commit `ce2b537` | — |
| Gate L.1 — eBPF-triggered adaptive discovery (trigger provenance, priority ordering) | GREEN | `ebpf-triggered-discovery-evidence.txt` | feat/gate-l1-ebpf-triggered-discovery |
| Gate L.2 — local-interface scope + inbound eBPF discovery | GREEN | `gate-l2-local-interface-evidence.txt` | feat/gate-l2-local-interface-scope |
| Gate L.3 — ICMP packet-level stimulus sensing (physarum-packet-observer) | GREEN | `gate-l3-icmp-stimulus-evidence.txt` | Issue #87 |
| Gate M — physarum-node runtime (physarum-agent + eBPF observer as supervised children) | GREEN | `gate-m-node-runtime-evidence.txt` | feat/gate-m |
| Gate M.4 — scoring adapter / per-edge multiplier weighting | GREEN | branch `feat/pf1-pf2-pre-final-labs` | — |
| PF-1 — organic expansion maze (7-node AWS lab, autonomous SCP+SSH propagation, lineage) | GREEN | `ansible-pf1/` verification | feat/pf1-pf2-pre-final-labs |
| PF-2 — adaptive re-routing (9-node AWS lab, lateral discovery, cross-subnet TCP stimulus, secondary conduits) | GREEN | `ansible-pf2/` verification | commit `5ab1c40` |
| Docker A/B/C/D lab | GREEN | `check-docker-lab.sh`: 34 passed, 0 failed | PR #19 |
| GET /paths endpoint | GREEN | Docker `/paths` validation posted | PR #20 |
| Documentation workflow | GREEN | PR/issue templates + ownership guidelines merged | PR #23 |
| Roadmap | GREEN | Trimmed to current status + next steps only | PR #25 |
| Formal model (TLA+) — single edge | GREEN | `PhysarumEdgeModel.tla` TypeOK + Safety verified | PR #12 |
| B/C/D TLA+ Path-Selection Model | GREEN | TypeOK + Safety + PathSelectionSafety verified; 148,877 distinct states (upper bound 11⁶ = 1,771,561); parse fix included | PR #56 |
| AWS lab design | GREEN | A/B/C/D Terraform skeleton designed | PR #29 |
| AWS Terraform skeleton | GREEN | Skeleton implemented under `examples/aws-lab/terraform/` | PR #31 |
| AWS v0 smoke test | GREEN | 32 resources created/destroyed; `terraform destroy` clean | PR #33 |
| AWS default cost/security posture | GREEN | `t3.micro`/`x86_64` default; `<OPERATOR_IP>/32` documented | PR #35 |
| AWS S3 artifact delivery + IAM role | GREEN | S3 bucket + least-privilege IAM role + Instance Profile provisioned | PR #38 |
| AWS SSH + Ansible validation model | GREEN | Port 8080 removed from public SG; Ansible replaces curl for runtime validation | PR #42 |
| AWS Mode 1 Runtime Validation | GREEN | failed=0 on all nodes; /health /agents /graph /paths confirmed; 39 resources destroyed | PR #43 |
| AWS Phase Identity (`lab_phase` variable) | GREEN | `lab_phase` variable, `effective_name_prefix`, phase tags, and SG `count` rules implemented | PR #45 |
| AWS Mode 2 Segmented B→C→D Runtime Validation | GREEN | failed=0 on all nodes; `/paths B→D` routes exclusively via C; 37 resources destroyed | PR #51 |
| Weighted Competing Paths Validation | GREEN | 2 phases PASS; B→C→D is top selected path (score 0.693) when E degraded 50% (Phase 1); B→E→D becomes top selected path (score 0.694) when C degraded 50% (Phase 2); top path changes; no direct B→D; evidence in weighted-paths-evidence.txt | PR #57 |
| AWS tc/netem Weighted Competing Paths | GREEN | 2 phases PASS in real EC2/VPC; Phase 1 top=B→C→D (score 0.694, E degraded); Phase 2 top=B→E→D (score 0.688, C degraded); top path switches; 50 resources destroyed clean; evidence in weighted-paths-aws-evidence.txt | Issue #58 |
| FlowObservation model + POST/GET /flow-observations | GREEN | 64 tests passing; ring buffer eviction validated; no eBPF runtime | PR #68 |
| Gate J — eBPF Observer Runtime (AWS EC2) | GREEN | kernel 6.18; tracepoint attached; FlowObservation posted; failed=0; metadata-only confirmed | Issue #69 |
| Gate J.1 — eBPF observer agent-b → agent-c flow correlation | GREEN | destination_ip=10.50.30.10, port=9002, direction=outbound, event=connect_established confirmed; q_ema≈1.0; failed=0; 42 resources destroyed | Issue #72 |
| Gate K — segmented adaptive flow-path A/B/C/D/E lab | GREEN | failed=0 all nodes; B→E FlowObs confirmed; q_ema>0 on B→E, C→D, D→E; C→E absent; degradation avg_rtt_ms=130.1ms PASS; recovery avg_rtt_ms=8.55ms PASS; 46 resources destroyed | Issue #76 — 4 documented limitations; see note below |
| Gate K.1 — autonomous path selection and tie-breaking | GREEN | failed=0 all nodes; Phase 1: selected_path=B→E score=1.0, B→C→D→E secondary_conduit score=0.9047; Phase 2: selected_path switched to B→C→D→E (B→E q_ema=0.8508 avg_rtt_ms=120.75); Phase 3: selected_path reverted to B→E (q_ema=0.9358 score=0.9550); 46 resources destroyed | Issue #80 / PR #82 |
| Gate N — mTLS + Ed25519 lineage signatures | FUTURE | Not started | Planned after physarum-llm |
| physarum-llm — LLM-aware adaptive propagation | FUTURE | Issue #106 — architecture documented | Planned |
| Security hardening / API auth | FUTURE | Port 8080 unauthenticated; Security Group is sole access control | Deferred until auth layer added |
| Persistence / replay | FUTURE | Not scoped | Deferred |
| WASM visual simulation | FUTURE | Plan documented, no impl yet | Deferred |

**GREEN** for PF-2 — Adaptive Re-routing — 9-node AWS lab (terraform-pf2); topology: A (seed, front 10.60.10.0/24), A.1 (lateral, same subnet, appears T+5min via Terraform time_sleep), B/C (layer-1 10.60.20.0/24), D/E/F (layer-2 10.60.30.0/24), G (layer-3 milestone 10.60.40.0/24), X (cross-subnet 10.60.50.0/24, appears T+5min); three adaptive behaviors validated: (1) A discovers A.1 (10.60.10.20) via /24 nmap — A.1 in A's lineage.visited; (2) X sends TCP SYN to A.1:22 every 30s via bash /dev/tcp built-in — A.1 discovers X → propagates; (3) X detects G already colonized → secondary_conduits=[X_IP,G_IP] (score ×0.8 ×1.2); Ansible PLAY RECAP all nodes failed=0; 9 EC2 instances created + destroyed; fixes: nc→bash /dev/tcp (nc absent on AL2023), Ansible ICMP tests replaced with journal-based verification (SG rules are unidirectional), operator IP masked as <OPERATOR_IP>; commit 5ab1c40 on feat/pf1-pf2-pre-final-labs.  
**GREEN** for PF-1 — Organic Expansion Maze — 7-node AWS lab (terraform-pf1); topology: A (seed, front), B/C (layer-1), D/E/F (layer-2), G (layer-3 milestone); autonomous propagation validated end-to-end: A→C→E→F→G in 55 seconds via SCP binary + empty-password SSH + systemd-run; lineage JSON recorded at each hop (origin, path, hops, visited, scores, colonized); dead end D scored ×0.05 (decay); physarum-maze binary built via Docker Build Cloud (cloud-expertsonline-physarum-attack-paths), deployed via S3 + EC2 user_data; Ansible ansible-pf1 verification passed; resources created + destroyed.  
**GREEN** for Gate M.4 — Scoring Adapter — per-edge multiplier model implemented in physarum-maze: productive hop ×1.5, dead end ×0.05, already-colonized ×0.8, secondary conduit ×1.2; scores persisted in physarum-lineage.json under scores map keyed by "src_ip:dst_ip"; branch feat/pf1-pf2-pre-final-labs.  
**GREEN** for Gate M — physarum-node Runtime — 3-node AWS lab (lab_phase=gate-m); physarum-node binary supervises physarum-agent and physarum-ebpf-observer as systemd children; Evidence 1: physarum-node.service active; Evidence 2: physarum-agent and physarum-ebpf-observer are child PIDs of physarum-node PID 2030; Ansible PLAY RECAP agent-b ok=35 failed=0; 42 resources created + destroyed; physarum-node built via Docker Build Cloud (cloud-fs09-physarum-attack-paths), uploaded to S3.  
**GREEN** for Gate L.3 — ICMP Packet-Level Stimulus Sensing — physarum-packet-observer deployed with ICMP-only mode (enable_discovery=false, sense_icmp_packet=true); inbound ICMP echo-request from node B (10.50.20.20) and node C (10.50.20.30) received by node A (10.50.20.10); ICMP seed → /32 exact-host scan via physarum-scanner; discovered sockets promoted to probe targets; Ansible PLAY RECAP node_A ok=62 failed=0, node_B ok=3 failed=0, node_C ok=3 failed=0; physarum-packet-observer-ebpf (4.0K bpfel-unknown-none) built via Docker Build Cloud; Issue #87.  
**GREEN** for Gate L.2 — Local-Interface Scope + Inbound eBPF Discovery — 3-node single-subnet lab (10.50.20.0/24, lab_phase=gate-l2); eBPF-triggered inbound discovery from node_b (10.50.20.20) and node_c (10.50.20.30) confirmed on node_a (10.50.20.10); discovery_method=physarum-scanner in all candidate-discoveries responses; Ansible PLAY RECAP node_a ok=54 failed=0, node_b ok=3 failed=0, node_c ok=3 failed=0; 42 resources created + destroyed; branch feat/gate-l2-local-interface-scope.  
**GREEN** for Gate L.1 — eBPF-Triggered Adaptive Discovery — trigger provenance fix (DiscoveryTrigger::priority() — EbpfNewInboundHost/EbpfNewOutboundHost priority 2 > Scheduled priority 1 > Startup priority 0); eBPF seed scan starting confirmed in agent log; "eBPF seed discovery report posted ip=10.50.50.10" confirmed; ebpf_trigger_not_overwritten_by_later_scheduled_discovery test passed; commit 6b50ee7; branch feat/gate-l1-ebpf-triggered-discovery; evidence in ebpf-triggered-discovery-evidence.txt.  
**GREEN** for Gate L — physarum-scanner Crate — full RustScan feature parity: async TCP/UDP scanning, CIDR/DNS resolution, LCG port ordering, scripting engine (nmap payloads via build.rs), rlimit management (infer_batch_size ported from RustScan main.rs), standalone physarum-scan binary; cargo test all passing; commit ce2b537.  
**GREEN** for Gate K.1 — Autonomous Path Selection — 5-node AWS lab (lab_phase=gate-k, enable_observer=true); topology: B↔C(peers), B→E(direct), C→D→E(indirect), C→E blocked by SG; scoring model: score=exp(-(sum(-ln(max(q_ema,0.001)))+0.05*(hops-1))) (HOP_WEIGHT=0.05, Q_EMA_FLOOR=0.001, SECONDARY_CONDUIT_THRESHOLD=0.85); Phase 1 healthy: B→E q_ema=1.0 score=1.0 selected_path=[agent-b,agent-e]; B→C→D→E score=0.9047 in secondary_conduits; Phase 2 degraded (tc/netem 200ms±50ms 10%loss via u32 filter to 10.50.50.10/32): B→E q_ema=0.8508 avg_rtt_ms=120.75 score=0.8598; B→C→D→E score=0.9048 wins; selected_path switches to [agent-b,agent-c,agent-d,agent-e]; Phase 3 recovery (tc removed, 180s wait): B→E q_ema=0.9358 avg_rtt_ms=7.5 score=0.9550; B→C→D→E score=0.9048; selected_path reverts to [agent-b,agent-e]; Ansible PLAY RECAP agent-b ok=20 failed=0, server-a ok=28 failed=0; 46 resources created + destroyed. NOTE: ranking flip verified at Level 2 (automatic path re-selection by /paths endpoint). HOP_WEIGHT=0.05 calibrated for this topology: healthy 3-hop beats degraded 1-hop when q_ema drops below ~0.91 on the direct edge. B→E q_ema=0.9358 at recovery (not full 1.0 — 18/20 window slots flushed in 180s); score=0.9550 > 0.9048 is sufficient for correct reselection before full EMA recovery.  
**GREEN** for Gate K — Segmented Adaptive Flow-Path Lab — 5-node AWS lab (lab_phase=gate-k, enable_observer=true); topology: B↔C(peers), B→E(direct), C→D→E(indirect), C→E blocked by SG; Test 1: B→E FlowObservation (destination_ip=10.50.50.10, destination_port=9004, direction=outbound, event=connect_established); B→E q_ema=0.9999, C→D q_ema=0.9997, D→E q_ema=0.9998; C→E edge absent (SG enforcement confirmed); Test 2: direct B→E avg_rtt_ms=0.05ms vs indirect C→D avg_rtt_ms=0.1ms, D→E avg_rtt_ms=0.1ms; sample_count=20; FlowObservation count gap documented (no observer on agent-c/agent-d); Test 3: baseline B→E avg_rtt_ms=0.05ms; Phase 2 degradation (tc/netem 200ms±50ms 10%loss via u32 filter to 10.50.50.10/32): B→E avg_rtt_ms=130.1ms CONFIRMED (>50ms), C→D q_ema=0.9999 CONFIRMED (indirect healthy); Phase 3 recovery (tc removed, 180s wait): B→E avg_rtt_ms=8.55ms CONFIRMED (<50ms); Ansible PLAY RECAP agent-b ok=20 failed=0, server-a ok=33 failed=0; 46 resources created + destroyed. NOTE: WINDOW_SIZE=20 × probe_interval=10s = 200s full flush time; 180s recovery wait sufficient (18/20 window slots cleared). Process attribution (comm=mandb) is expected for async TCP connections; 5-tuple uniquely identifies B→E physarum probe flow. DOCUMENTED LIMITATIONS: (1) Segment semantics — B (10.50.20.10) and C (10.50.30.10) are modelled as logical peers via SG reachability; they reside in different AWS subnets (10.50.20.0/24 and 10.50.30.0/24 respectively); strict same-subnet semantics not implemented in gate-k. (2) Path forwarding semantics — C→D→E is a logical multi-hop graph path (agent-c probes agent-d directly; agent-d probes agent-e directly); there is no network-layer packet forwarding or proxying through D. (3) Adaptation semantics — Test 3 validates that B→E probe metrics degrade and recover under tc/netem; the Physarum organism observes the degradation via q_ema changes but automatic path re-selection (organism traffic shifting from B→E to C→D→E during degradation) was not captured; /paths ranking during Phase 2 degradation was not recorded; that measurement is future work. (4) Flow count coverage — eBPF observer is present on agent-b only; per-edge FlowObservation counts for C→D and D→E are unavailable; those edges are confirmed exclusively via graph q_ema>0 and sample_count=20; extending observers to agent-c and agent-d is deferred to a future gate (Issue #76).  
**GREEN** for Gate J.1 — eBPF Observer Agent Flow Correlation — FlowObservation (destination_ip=10.50.30.10, destination_port=9002, direction=outbound, event=connect_established) confirmed for physarum-agent → agent-c probe; agent-b → agent-c graph edge q_ema≈1.0 (sample_count=20); Ansible PLAY RECAP agent-b ok=17 failed=0, server-a ok=14 failed=0; 42 resources created + destroyed. NOTE: tracepoint/sock/inet_sock_set_state fires in softirq context — comm=swapper/0 (kernel idle at state change time) is expected for async connections; the 5-tuple uniquely identifies the physarum probe flow; process attribution improvement deferred to a future gate (Issue #72).  
**GREEN** for Gate J — eBPF Observer Runtime — `physarum-ebpf-observer` binary + `physarum-ebpf-observer-ebpf` eBPF bytecode deployed to EC2 (AL2023, kernel 6.18.25); observer attached to `tracepoint/sock/inet_sock_set_state`; FlowObservation events (source_ip, destination_ip, source_port, destination_port, protocol, direction, event, pid, comm) posted to coordinator and confirmed via `GET /flow-observations`; metadata-only (no payload fields); Ansible PLAY RECAP agent-b ok=21 failed=0, server-a ok=8 failed=0; 42 resources created + destroyed (Issue #69).  
**GREEN** for Gate I — FlowObservation Model and Server Endpoints — `FlowObservation` struct + `FlowDirection`/`FlowEvent`/`FlowProtocol` enums (snake_case serde) added to `physarum-protocol`; `POST /flow-observations` (201 Created, in-memory VecDeque ring buffer, capacity 1000, oldest evicted on overflow); `GET /flow-observations` (limit + agent_id filter); 14 new tests (8 protocol + 6 endpoint); 64 total tests pass; no eBPF runtime, Aya, kernel tracepoint, RustScan, or scoring integration (PR #68). Scope: protocol model, server endpoints, in-memory bounded buffer, tests. Next gate: Gate J — physarum-ebpf-observer runtime prototype and AWS EC2 validation.  
**Overall GREEN** for the Adaptive Path Prototype gate — all Phase 1 milestones complete.  
**GREEN** for AWS Mode 1 Runtime — full-mesh validated in real EC2/VPC, Ansible recap failed=0 on all nodes.  
**GREEN** for AWS Phase Identity — `lab_phase` variable, resource naming, tagging, and SG topology implemented (PR #45).  
**GREEN** for AWS Mode 2 Runtime — segmented B→C→D topology validated in real EC2/VPC; `/paths B→D` routes exclusively via C; 37 resources destroyed cleanly (PR #51).  
**GREEN** for B/C/D TLA+ Path-Selection Model — scoped model covers edges B→C, C→D, B→D; TypeOK, Safety, and PathSelectionSafety verified; 148,877 distinct states reachable (upper bound 11⁶ = 1,771,561); PathSelectionSafety formalises the binary Mode 2 case only (PR #56).  
**GREEN** for Weighted Competing Paths — 2-phase Docker validation passed with true top-path re-selection: no direct B→D edge (agent-b uses `--probe-targets agent-c,agent-e`); Phase 1 top path = B→C→D (score 0.693, E degraded 50%); Phase 2 top path re-selects to B→E→D (score 0.694, C degraded 50%); the selected top path changes between phases; success_rate-based scoring produces ~20% score separation between degraded and healthy multi-hop alternatives (PR #57).  
**GREEN** for AWS tc/netem Weighted Competing Paths — 2-phase real EC2/VPC validation passed; 50 resources (us-east-1, lab_phase=weighted-paths); Phase 1: B→C→D top (score 0.694) when E degraded via tc/netem (100ms±20ms / 5% loss); Phase 2: B→E→D top (score 0.688) when C degraded; top path switches between phases; tc qdiscs cleaned up; terraform destroy clean (50 resources); score separation Δ~5–7%; evidence in weighted-paths-aws-evidence.txt (Issue #58).

---

## AWS lab baseline (as of PR #35)

```text
Default instance_type : t3.micro
Default architecture  : x86_64
AMI                   : Amazon Linux 2023 (SSM dynamic lookup — no hard-coded AMI ID)
Operator CIDR         : <OPERATOR_IP>/32  (Dev Lead workstation)
Inbound 0.0.0.0/0     : NOT PRESENT — validation enforced in variables.tf
NAT Gateway           : NOT provisioned
ALB / NLB             : NOT provisioned
Elastic IP            : NOT provisioned
RDS / EKS             : NOT provisioned
Terraform state       : local only (S3 remote deferred)
v0 smoke test         : PASSED — 32 resources created, validated, destroyed
Runtime endpoints     : NOT yet validated in AWS
```

---

## Completed gates

| Gate | Status |
|---|---|
| Adaptive Edge Prototype (Phase 1A–1C) | COMPLETED |
| Local A/B/C Lab | COMPLETED |
| Docker A/B/C Lab | COMPLETED |
| TLA+ Edge Model | COMPLETED |
| Docker A/B/C/D Lab | COMPLETED |
| Basic Adaptive Path Prototype (GET /paths) | COMPLETED |
| Documentation workflow (templates + guidelines) | COMPLETED — PR #23 |
| Roadmap cleanup after /paths milestone | COMPLETED — PR #25 |
| AWS Lab Terraform skeleton design | COMPLETED — PR #29 |
| AWS Lab Terraform skeleton implementation | COMPLETED — PR #31 |
| AWS Lab Terraform v0 smoke test | COMPLETED — PR #33 |
| AWS Lab Intel Default and Operator CIDR Hardening | COMPLETED — PR #35 |
| AWS S3 Artifact Delivery and EC2 Runtime Bootstrap | COMPLETED — PR #38 |
| AWS SSH + Ansible Validation Model | COMPLETED — PR #42 |
| AWS Mode 1 Runtime Validation (full mesh) | COMPLETED — PR #43 |
| AWS Phase Identity (`lab_phase` variable) | COMPLETED — PR #45 |
| AWS Mode 2 Segmented B→C→D Runtime Validation | COMPLETED — PR #51 |
| B/C/D TLA+ Path-Selection Model | COMPLETED — PR #56 |
| Weighted Competing Paths Validation | COMPLETED — PR #57 |
| AWS tc/netem Weighted Competing Paths Validation | COMPLETED — Issue #58 |
| Gate I — FlowObservation Model and Server Endpoints | COMPLETED — PR #68 |
| Gate J — eBPF Observer Runtime Validation | COMPLETED — Issue #69 |
| Gate J.1 — eBPF Observer Agent Flow Correlation | COMPLETED — Issue #72 |
| Gate K — Segmented Adaptive Flow-Path Lab | COMPLETED — Issue #76 |
| Gate K.1 — Autonomous Path Selection (negative-log scoring) | COMPLETED — Issue #80 / PR #82 |
| Gate L — physarum-scanner crate (RustScan feature parity) | COMPLETED — commit ce2b537 |
| Gate L.1 — eBPF-triggered adaptive discovery (trigger provenance) | COMPLETED — feat/gate-l1-ebpf-triggered-discovery |
| Gate L.2 — local-interface scope + inbound eBPF discovery | COMPLETED — feat/gate-l2-local-interface-scope |
| Gate L.3 — ICMP packet-level stimulus sensing | COMPLETED — Issue #87 |
| Gate M — physarum-node runtime (supervised children) | COMPLETED — feat/gate-m |
| Gate M.4 — scoring adapter / per-edge multiplier weighting | COMPLETED — feat/pf1-pf2-pre-final-labs |
| PF-1 — Organic Expansion Maze (7-node AWS lab) | COMPLETED — feat/pf1-pf2-pre-final-labs |
| PF-2 — Adaptive Re-routing (9-node AWS lab) | COMPLETED — commit 5ab1c40 |

---

## Active gate

No active gate. PF-2 complete. Next gate: Gate N (mTLS + Ed25519 lineage signatures) — pending physarum-llm (Issue #106) prioritisation decision.

---

## Previous active gate (now completed)

**PF-2 — Adaptive Re-routing**  
Branch: feat/pf1-pf2-pre-final-labs · Commit: 5ab1c40  
Entry criteria: PF-1 organic expansion maze complete. ✔  
Scope: 9-node AWS lab with three adaptive behaviors — lateral discovery via /24 nmap, cross-subnet TCP stimulus (X→A.1:22 via bash /dev/tcp), and secondary conduit detection when G already colonised.  
Exit criteria met: A.1 (10.60.10.20) present in A's lineage.visited; X propagated from A.1 (X's lineage present); X's secondary_conduits=[X_IP,G_IP] non-empty; G binary present + unit ran; all Ansible verification tasks passed (failed=0); 9 EC2 instances destroyed.

---

## Gate sequence ahead

| Gate | Tracked by | Status |
|---|---|---|
| A — Design S3 artifact delivery and EC2 bootstrap | Issue #36 | COMPLETED |
| B — Implement S3 delivery + IAM role + real `user_data` | PR #38 | COMPLETED |
| C — Validate AWS Mode 1 full mesh runtime | PR #43 | COMPLETED |
| D — Phase identity (`lab_phase` variable + SG rules) | PR #45 | COMPLETED |
| E — AWS Mode 2 segmented B→C→D runtime validation | PR #51 | COMPLETED |
| F — B/C/D TLA+ Path-Selection Model | Issue #55 / PR #56 | COMPLETED |
| G — Weighted Competing Paths Validation | Issue #52 / PR #57 | COMPLETED |
| H — AWS tc/netem Weighted Competing Paths Validation | Issue #58 | COMPLETED |
| I — FlowObservation Model and Server Endpoints | Issue #66 / PR #68 | COMPLETED |
| J — eBPF Observer Runtime (AWS EC2) | Issue #69 | COMPLETED |
| J.1 — eBPF Observer Agent Flow Correlation | Issue #72 | COMPLETED |
| K — Segmented Adaptive Flow-Path Lab | Issue #76 | COMPLETED |
| K.1 — Autonomous Path Selection (negative-log scoring) | Issue #80 / PR #82 | COMPLETED |
| L — physarum-scanner crate (RustScan feature parity) | commit ce2b537 | COMPLETED |
| L.1 — eBPF-triggered adaptive discovery | feat/gate-l1 | COMPLETED |
| L.2 — local-interface scope + inbound eBPF discovery | feat/gate-l2 | COMPLETED |
| L.3 — ICMP packet-level stimulus sensing | Issue #87 | COMPLETED |
| M — physarum-node runtime (supervised children) | feat/gate-m | COMPLETED |
| M.4 — scoring adapter / per-edge multiplier weighting | feat/pf1-pf2-pre-final-labs | COMPLETED |
| PF-1 — organic expansion maze (7-node AWS) | feat/pf1-pf2-pre-final-labs | COMPLETED |
| PF-2 — adaptive re-routing (9-node AWS) | commit 5ab1c40 | COMPLETED |
| physarum-llm — LLM-aware adaptive propagation | Issue #106 | PLANNED |
| N — mTLS + Ed25519 lineage signatures | — | PLANNED |

---

## Open blockers

```text
- coordinator API (port 8080) unauthenticated — operator_cidr must remain a narrow /32
```

---

## Known risks

```text
- AWS work may introduce infrastructure complexity if started before scope is agreed
- Documentation can drift if PROTOTYPE_ROADMAP.md starts tracking issue history again
- operator_cidr must remain a narrow /32 until coordinator API authentication is added
- arm64 binary cross-compilation requires additional CI toolchain setup if Graviton path is validated
- latency-based quality discrimination requires AWS with tc/netem; Docker localhost RTTs are indistinguishable (sub-ms)
```

---

## Project quality rules

```text
Design before implementation
Runtime validation before merge
Docs describe only what is currently implemented
One primary doc file per feature PR
GitHub Issues/PRs are the detailed historical record
```

See [General-Docs/DOCUMENTATION_GUIDELINES.md](DOCUMENTATION_GUIDELINES.md) for the full documentation ownership model.

---

## How to read this page

This page answers: **are we ready for the next phase?**

- If all checklist rows are GREEN → yes, advance.
- If any row is YELLOW → identify the blocking item and close it before advancing.
- If any row is RED → stop, fix the blocker first.
- FUTURE rows are tracked here for visibility but do not block the current gate.

For detailed validation output, issue history, and delivery notes see the linked GitHub Issues and PRs.  
For the implementation sequence see [General-Docs/PROTOTYPE_ROADMAP.md](PROTOTYPE_ROADMAP.md).

# Quality Gate — Physarum Attack Paths

**Current gate:** Weighted Competing Paths Validation — COMPLETED  
**Overall status:** GREEN (Adaptive Path Prototype) · GREEN (AWS Mode 1 Runtime) · GREEN (AWS Phase Identity) · GREEN (AWS Mode 2 Runtime) · GREEN (B/C/D TLA+ Path-Selection Model) · GREEN (Weighted Competing Paths)  
**Last updated:** 2026-05-09

> GREEN = ready to advance · YELLOW = usable, follow-up required · RED = blocked or unstable · FUTURE = planned, not blocking current gate

---

## Gate checklist

| Area | Status | Evidence | Notes |
|---|---|---|---|
| Build / test health | GREEN | 51 tests passing | `cargo test --workspace` — 18 agent + 5 protocol + 28 server; last verified PR #57 |
| Docker A/B/C/D lab | GREEN | `check-docker-lab.sh`: 34 passed, 0 failed | PR #19 |
| GET /paths endpoint | GREEN | Docker `/paths` validation posted | PR #20 |
| Documentation workflow | GREEN | PR/issue templates + ownership guidelines merged | PR #23 |
| Roadmap | GREEN | Trimmed to current status + next steps only | PR #25 |
| Formal model (TLA+) — single edge | GREEN | `PhysarumEdgeModel.tla` TypeOK + Safety verified | PR #12 |
| B/C/D TLA+ Path-Selection Model | GREEN | TypeOK + Safety + PathSelectionSafety verified; 148,877 distinct states (upper bound 11⁶ = 1,771,561); parse fix included | PR #56 |
| AWS lab design | GREEN | A/B/C/D Terraform skeleton designed | PR #29 |
| AWS Terraform skeleton | GREEN | Skeleton implemented under `examples/aws-lab/terraform/` | PR #31 |
| AWS v0 smoke test | GREEN | 32 resources created/destroyed; `terraform destroy` clean | PR #33 |
| AWS default cost/security posture | GREEN | `t3.micro`/`x86_64` default; `187.101.126.140/32` documented | PR #35 |
| AWS S3 artifact delivery + IAM role | GREEN | S3 bucket + least-privilege IAM role + Instance Profile provisioned | PR #38 |
| AWS SSH + Ansible validation model | GREEN | Port 8080 removed from public SG; Ansible replaces curl for runtime validation | PR #42 |
| AWS Mode 1 Runtime Validation | GREEN | failed=0 on all nodes; /health /agents /graph /paths confirmed; 39 resources destroyed | PR #43 |
| AWS Phase Identity (`lab_phase` variable) | GREEN | `lab_phase` variable, `effective_name_prefix`, phase tags, and SG `count` rules implemented | PR #45 |
| AWS Mode 2 Segmented B→C→D Runtime Validation | GREEN | failed=0 on all nodes; `/paths B→D` routes exclusively via C; 37 resources destroyed | PR #51 |
| Weighted Competing Paths Validation | GREEN | 2 phases PASS; B→C→D is top selected path (score 0.693) when E degraded 50% (Phase 1); B→E→D becomes top selected path (score 0.694) when C degraded 50% (Phase 2); top path changes; no direct B→D; evidence in weighted-paths-evidence.txt | PR #57 |
| Security hardening / API auth | FUTURE | Port 8080 unauthenticated; Security Group is sole access control | Deferred until auth layer added |
| Persistence / replay | FUTURE | Not scoped | Deferred |
| WASM visual simulation | FUTURE | Plan documented, no impl yet | Deferred |

**Overall GREEN** for the Adaptive Path Prototype gate — all Phase 1 milestones complete.  
**GREEN** for AWS Mode 1 Runtime — full-mesh validated in real EC2/VPC, Ansible recap failed=0 on all nodes.  
**GREEN** for AWS Phase Identity — `lab_phase` variable, resource naming, tagging, and SG topology implemented (PR #45).  
**GREEN** for AWS Mode 2 Runtime — segmented B→C→D topology validated in real EC2/VPC; `/paths B→D` routes exclusively via C; 37 resources destroyed cleanly (PR #51).  
**GREEN** for B/C/D TLA+ Path-Selection Model — scoped model covers edges B→C, C→D, B→D; TypeOK, Safety, and PathSelectionSafety verified; 148,877 distinct states reachable (upper bound 11⁶ = 1,771,561); PathSelectionSafety formalises the binary Mode 2 case only (PR #56).  
**GREEN** for Weighted Competing Paths — 2-phase Docker validation passed with true top-path re-selection: no direct B→D edge (agent-b uses `--probe-targets agent-c,agent-e`); Phase 1 top path = B→C→D (score 0.693, E degraded 50%); Phase 2 top path re-selects to B→E→D (score 0.694, C degraded 50%); the selected top path changes between phases; success_rate-based scoring produces ~20% score separation between degraded and healthy multi-hop alternatives (PR #57).

---

## AWS lab baseline (as of PR #35)

```text
Default instance_type : t3.micro
Default architecture  : x86_64
AMI                   : Amazon Linux 2023 (SSM dynamic lookup — no hard-coded AMI ID)
Operator CIDR         : 187.101.126.140/32  (Dev Lead workstation)
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

---

## Active gate

None — all gates in the current sequence are complete. Next gate to be defined.

---

## Previous active gate (now completed)

**Weighted Competing Paths Validation**  
Tracked by: Issue #52  
Entry criteria: Multi-Agent TLA+ formal verification passed (PR #56). ✔  
Scope: Validate that when multiple valid competing paths exist with different observed quality, the system selects the highest-quality path by score and re-ranks dynamically when quality changes.  
Exit criteria: At least two valid competing paths; intentionally different observed quality; `/paths` ranks the higher-quality path first; after degrading the preferred path, `/paths` re-ranks to the better alternative; results documented with before/after evidence.

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

---

## Next proposed gate

To be defined. All current validation gates are complete.

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

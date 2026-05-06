# Quality Gate — Physarum Attack Paths

**Current gate:** AWS Lab Intel Default and Operator CIDR Hardening  
**Overall status:** GREEN  
**Last updated:** 2026-05-06

> GREEN = ready to advance · YELLOW = usable, follow-up required · RED = blocked or unstable

---

## Gate checklist

| Area | Status | Evidence | Notes |
|---|---|---|---|
| Build | GREEN | `cargo fmt/clippy/test` passing | Last verified PR #20, PR #25, PR #29, PR #33 |
| Docker A/B/C/D lab | GREEN | `check-docker-lab.sh`: 34 passed, 0 failed | PR #19 |
| GET /paths endpoint | GREEN | Docker `/paths` validation posted | PR #20 |
| Documentation | GREEN | Roadmap trimmed; AWS lab designed and smoke-tested | PR #25, PR #29, PR #33 merged |
| Formal model (TLA+) | GREEN | `PhysarumEdgeModel.tla` TypeOK + Safety verified | PR #12 |
| AWS readiness | YELLOW | Skeleton smoke-tested; Intel default pending | PR #33 merged; Issue #34 / PR #35 open |
| WASM readiness | YELLOW | Visual-sim plan documented, no impl yet | Future phase |

**Overall GREEN** for the Adaptive Path Prototype gate.  
AWS is YELLOW because Issue #34 (Intel default + operator CIDR hardening) is open.

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
| Documentation workflow (templates + guidelines) | COMPLETED |
| Roadmap cleanup after /paths milestone | COMPLETED — PR #25 |
| AWS Lab Terraform skeleton design | COMPLETED — PR #29 |
| AWS Lab Terraform skeleton implementation | COMPLETED — PR #31 |
| AWS Lab Terraform v0 smoke test | COMPLETED — PR #33 |

---

## Active gate

**AWS Lab Intel Default and Operator CIDR Hardening**  
Tracked by: Issue #34 / PR #35  
Scope: Switch default instance type to `t3.micro` / `x86_64` (Intel/Free Tier-oriented). Document explicit operator CIDR `187.101.126.140/32` in README examples and explain security rationale (coordinator API not yet authenticated). Keep Graviton/t4g path documented as optional.  
Exit criteria: PR #35 merged; `terraform fmt` and `terraform validate` pass; no `0.0.0.0/0` introduced; Graviton path not deleted.

---

## Next proposed gate

**AWS Lab Binary Artifact Pipeline and Runtime Validation**  
Entry criteria: Issue #34 closed, PR #35 merged.  
Scope: Build `linux-x86_64` (and optionally `linux-arm64`) Rust binaries, upload to S3, add EC2 IAM role with `s3:GetObject`, update `user_data` to download binaries, start real systemd services, validate `/health`, `/agents`, `/graph`, `/paths` in Mode 1 (full mesh). Then validate Mode 2 (segmented B→C→D).

---

## Open blockers

```text
- Issue #34 / PR #35 open: switch to Intel default and document operator CIDR
- Binary artifact pipeline not started (required for runtime validation)
```

---

## Known risks

```text
- AWS work may introduce infrastructure complexity if started before scope is agreed
- TLA+ model covers only one edge; multi-agent formal properties are unverified
- Documentation can drift if PROTOTYPE_ROADMAP.md starts tracking issue history again
- operator_cidr must remain a narrow /32 until coordinator API authentication is added
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

For detailed validation output, issue history, and delivery notes see the linked GitHub Issues and PRs.  
For the implementation sequence see [General-Docs/PROTOTYPE_ROADMAP.md](PROTOTYPE_ROADMAP.md).

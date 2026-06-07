# Quality Gate — Physarum Attack Paths

**Current gate:** PF-6 Phase 2 — ephemeral-key SCP propagation and lineage continuation  
**Active issue:** #141  
**Overall status:** YELLOW — Phase 1 is complete; Phase 2 execution proof is active  
**Last updated:** 2026-06-07

> GREEN = validated and ready to advance · YELLOW = active or usable with follow-up required · RED = blocked · FUTURE = planned, not blocking the current gate

---

## Current decision

The project has completed the architecture and evidence gates through PF-6 Phase 1.

```text
PF-4    COMPLETE — real LLM Docker validation
PF-5    COMPLETE — adaptive startup/runtime sensing
PF-5.2  COMPLETE — dynamic vulnerability intelligence
PF-6.0  COMPLETE — design and documentation
PF-6.1  COMPLETE — multi-target Phase 1 evidence
PF-6.2  ACTIVE   — ephemeral-key SCP propagation and lineage continuation
```

The project must not advance to the controlled AWS LLM Lab until Issue #141 proves the complete Docker propagation path without hardcoded success conditions.

---

## Current gate checklist

| Area | Status | Evidence | Notes |
|---|---|---|---|
| Build / test health | GREEN | CI and workspace checks | Current merged heads pass CI |
| Documentation synchronization | YELLOW | Issue #142 / PR #143 | README, architecture, quality gate, PF-6, and LLM design are being synchronized |
| PF-4 real LLM Docker validation | GREEN | PR #124 and PF-4 lineage evidence | OpenAI-compatible endpoint, real prompt/response path, PolicyGate, lineage |
| PF-5 adaptive sensing | GREEN | Issue #126 / PR #127 | Startup, ICMP, and TCP/eBPF profiles validated |
| PF-5.2 vulnerability intelligence | GREEN | Issue #131 / PR #132 | LocalAdvisoryCache, OsvFeed, affected ranges, vulnerability candidates |
| Nuclei-compatible sporangium engine | GREEN | PR #133 | Rust engine, matchers, extractors, protocols, workflows, template catalog |
| PF-6 design/documentation | GREEN | PR #138 | Multi-stage lab and template/LLM integration documented |
| PF-6 template wiring / compose | GREEN | PR #139 | YAML templates active in maze; advisory cache and compose added |
| PF-6 Phase 1 multi-target evidence | GREEN | PR #140 | Two-turn LLM flow, HTTP/TCP probing, automatic interface selection, lineage evidence |
| PF-6 Phase 2 ephemeral-key SCP | YELLOW | Issue #141 | Active execution gate |
| Controlled AWS LLM Lab | FUTURE | — | Starts only after #141 |
| Gate N secure identity | FUTURE | Issue #89 | mTLS, signed lineage, anti-replay, capability authorization |

---

## PF-6 Phase 2 advancement criteria

AWS work may begin only after Issue #141 proves all of the following in the existing PF-6 Docker lab:

```text
1. The Phase 1 pipeline remains unchanged in essence.
2. host-b and host-c are discovered dynamically.
3. The intended internal interface is selected automatically.
4. LLM Turn 1 receives compact template metadata.
5. Turn 1 selected template IDs are recorded.
6. Selected HTTP/TCP templates are actually executed.
7. Pattern findings reach VulnerabilityIntelService.
8. vulnerability_candidates are derived from observed evidence.
9. LLM Turn 2 returns an ordered typed strategy.
10. PolicyGate accepts only when Phase 2 is explicitly enabled.
11. host-a generates a temporary SSH keypair.
12. Only the public key is introduced on the selected target.
13. SCP transfers the current `__self__` physarum-maze binary.
14. SSH starts the target in propagated mode.
15. The propagated node continues the original lineage.
16. `colonized` is recorded only after real execution success.
17. Temporary key material is removed.
18. No target IP, CVE, template, finding, policy result, or success state is hardcoded.
```

A marker file alone is not sufficient proof.

---

## Historical completed gates

| Gate | Description | Status |
|---|---|---|
| A | S3 artifact delivery and bootstrap design | COMPLETED |
| B | S3 delivery, IAM role, and user data | COMPLETED |
| C | AWS Mode 1 full mesh runtime | COMPLETED |
| D | Phase identity | COMPLETED |
| E | AWS Mode 2 segmented topology | COMPLETED |
| F | TLA+ path-selection model | COMPLETED |
| G | Docker weighted competing paths | COMPLETED |
| H | AWS `tc/netem` weighted paths | COMPLETED |
| I | FlowObservation model and API | COMPLETED |
| J / J.1 | eBPF runtime and agent-flow correlation | COMPLETED |
| K / K.1 | Adaptive flow paths and autonomous selection | COMPLETED |
| L / L.1 / L.2 / L.3 | Native scanning and runtime stimulus sensing | COMPLETED |
| M / M.4 | Node runtime convergence and probe consolidation | COMPLETED |
| PF-1 | Organic expansion maze | COMPLETED |
| PF-2 | Adaptive re-routing and secondary conduits | COMPLETED |
| PF-4 | Real LLM Docker validation | COMPLETED |
| PF-5 | Adaptive sensing profiles | COMPLETED |
| PF-5.2 | Dynamic vulnerability intelligence | COMPLETED |
| PF-6.0 | Design/documentation | COMPLETED |
| PF-6.1 | Multi-target Phase 1 evidence | COMPLETED |
| PF-6.2 | Ephemeral-key SCP propagation | ACTIVE |

---

## Open blockers and risks

```text
- PF-6 Phase 2 has not yet produced successful SCP/SSH/propagated-mode lineage evidence.
- Node identity is not yet mTLS-backed.
- Lineage is structured but not cryptographically signed.
- Coordinator-era APIs remain historical and are not production-hardened.
- AWS adaptation must not introduce a second, simplified path that bypasses the Docker evidence contracts.
- Documentation drift must be prevented by keeping README, ARCHITECTURE, and QUALITY_GATE aligned.
```

---

## Project quality rules

```text
Design before implementation.
Runtime validation before completion.
Docs describe what is actually merged and proven.
The LLM proposes; PolicyGate decides.
No hardcoded success paths.
Detailed delivery history lives in GitHub Issues and PRs.
```

See `General-Docs/DOCUMENTATION_GUIDELINES.md` for ownership and synchronization rules.

---

## How to read this page

This page answers: **are we ready for the next phase?**

```text
All required rows GREEN -> advance.
Any required row YELLOW -> finish the active gate first.
Any required row RED -> stop and fix the blocker.
FUTURE rows -> visible but non-blocking.
```

Current answer: **not yet ready for AWS; complete Issue #141 first.**
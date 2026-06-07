# Documentation Guidelines

This document defines the documentation ownership model and contribution workflow for `physarum-attack-paths`.

The goal is to preserve the project's quality bar while reducing repetitive documentation work:

```text
design is documented
implementation follows the design
runtime lab proves the behavior
docs reflect what was actually proven
then we merge
```

---

## Central rule

**One feature PR should update at most one primary documentation file.**

If a change genuinely requires updating more than one primary file, the PR description must explicitly justify why. Exceptions are rare and should be flagged in review.

### Architectural synchronization exception

A cross-document synchronization PR may update multiple primary documentation files when the project state has drifted across authoritative documents.

This exception is allowed only when the PR:

```text
- references the synchronization issue
- lists every primary file touched
- explains why the update cannot be split without preserving contradictions
- does not change runtime code
- does not mark unproven behavior as complete
- keeps README, ARCHITECTURE, and QUALITY_GATE consistent
```

Example:

```text
README.md
General-Docs/ARCHITECTURE.md
General-Docs/QUALITY_GATE.md
General-Docs/PF6_TWO_CONTAINER_END_TO_END_DOCKER_LAB.md
crates/physarum-llm/DESIGN.md
```

---

## File ownership

Each file has a single responsibility. Do not duplicate content across files — use cross-links instead.

| File | Owns |
|---|---|
| `README.md` | Short project front door: what it is, current status, how to run the main labs, where to find more |
| `General-Docs/ARCHITECTURE.md` | Full system architecture across all generations — crates, gates, math, labs, implemented LLM-aware organism path |
| `General-Docs/QUALITY_GATE.md` | Current gate status, acceptance criteria, evidence links, and advancement decision |
| `General-Docs/PF6_TWO_CONTAINER_END_TO_END_DOCKER_LAB.md` | PF-6 Docker lab topology, invariants, Phase 1/Phase 2 model, and evidence requirements |
| `General-Docs/SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md` | Template catalog model and how `physarum-sporangium` exposes evidence to `physarum-maze` and the LLM |
| `crates/physarum-llm/DESIGN.md` | LLM contract decisions, schema boundaries, secret handling, two-turn reasoning flow, and phase status |
| `General-Docs/INSIGHTS_AND_BRAINSTORM.md` | Research ideas, future concepts, speculative notes |
| `General-Docs/ROLE_FLUID_AGENT_ARCHITECTURE.md` | Role-fluid agent design intent and eBPF stage sequence |
| `General-Docs/EBPF_FLOW_OBSERVATION_DESIGN.md` | eBPF Stage 0 design decisions — historical reference |
| `General-Docs/DOCUMENTATION_GUIDELINES.md` | This file — documentation workflow and ownership rules |
| `examples/local-lab/README.md` | Local lab runbook only |
| `examples/docker-lab/README.md` | Docker lab runbook only |
| `examples/aws-lab/README.md` | AWS lab overview and evidence index |
| `examples/wasm-lab/README.md` | WASM visual simulator plan only |
| `formal/tla/README.md` | TLA+ model usage, invariants, and formal-method notes |

---

## What each file must not contain

**`README.md`** must not contain:

- detailed milestone history that belongs in GitHub Issues/PRs
- long step-by-step lab runbooks that belong in `examples/*/README.md` or `docker/*.sh`
- long implementation notes that belong in `General-Docs/`
- claims that active gates are complete before evidence exists

**Lab READMEs** must not contain:

- cross-lab architecture content
- full project roadmap duplication
- speculative status not linked to the authoritative gate document

**`QUALITY_GATE.md`** must not contain:

- full PR narratives
- speculative design notes
- implementation details beyond gate evidence and advancement criteria

---

## Documentation accuracy rule

Documentation must describe what is currently implemented, not what we hope will be implemented.

```text
present tense -> implemented behavior
past tense    -> historical gates/labs
future tense  -> planned AWS/Gate N/future work
active         -> current work with an open issue/gate
```

Rules:

- Future or planned items must be clearly labeled as `planned`, `future`, or `active`.
- Do not update the status table in `README.md` until the corresponding PR is merged.
- Do not mark a gate as completed in `QUALITY_GATE.md` until the corresponding evidence exists and the PR is merged.
- Do not describe closed issues as active or next.
- Do not describe PF-6 Phase 2 as complete until Issue #141 has real evidence.
- Do not describe AWS validation as complete until the controlled AWS Lab has evidence.

---

## Cross-linking over duplication

When two documents need to reference the same content, the secondary document links to the primary. It does not reproduce the content.

Example:

```text
README.md -> short current status and links
ARCHITECTURE.md -> full system design
QUALITY_GATE.md -> advancement decision
GitHub Issues/PRs -> detailed delivery history and evidence
```

---

## ARCHITECTURE.md and QUALITY_GATE.md scope

`ARCHITECTURE.md` covers:

```text
Full system architecture across all generations
Crate layout, mathematical model, and current organism path
Implemented LLM-aware architecture
PF-6 Phase 1 / Phase 2 design boundaries
Historical PF-1/PF-2 mechanisms versus current PF-6 mechanisms
```

`QUALITY_GATE.md` covers:

```text
Current gate status
Completed / active / planned gate rows
Acceptance criteria and evidence links per gate
Known risks and gate advancement rules
```

Neither file should become a detailed per-issue archive. GitHub Issues and PRs are the permanent detailed record.

---

## PR documentation checklist

Every PR that touches documentation should verify:

- [ ] The change is in the correct primary file per the ownership table.
- [ ] No content is duplicated unnecessarily; cross-links are used where appropriate.
- [ ] Nothing is marked as implemented that is not yet merged or evidenced.
- [ ] Future/planned items are clearly labeled.
- [ ] The root `README.md` remains a short front door.
- [ ] Closed issues are not described as active or next.
- [ ] PF-6 Phase 1 and PF-6 Phase 2 terminology is used consistently.
- [ ] No runtime behavior is changed by a documentation PR.

For synchronization PRs, also verify:

- [ ] The PR references the synchronization issue.
- [ ] The PR body lists every primary document changed.
- [ ] README, ARCHITECTURE, and QUALITY_GATE agree on the active gate.
- [ ] Any exception to the one-primary-document rule is explicitly justified.

---

## GitHub Issues and PRs as the historical record

Detailed milestone tracking — who did what, when, what was validated, what output was produced — lives in GitHub Issues and PR bodies/comments.

`QUALITY_GATE.md` is the living advancement-status document. `ARCHITECTURE.md` is the authoritative design reference. `README.md` is the project front door.
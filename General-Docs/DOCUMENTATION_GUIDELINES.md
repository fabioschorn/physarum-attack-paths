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

---

## File ownership

Each file has a single responsibility. Do not duplicate content across files — use cross-links instead.

| File | Owns |
|---|---|
| `README.md` | Short project front door: what it is, how to run it, where to find more |
| `General-Docs/ARCHITECTURE.md` | Full system architecture across all generations — crates, gates, math, labs |
| `General-Docs/QUALITY_GATE.md` | Gate definitions, acceptance criteria, and evidence links |
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
- Detailed milestone history (that belongs in GitHub Issues/PRs)
- Step-by-step lab runbooks (those belong in `examples/*/README.md`)
- Long implementation notes (those belong in `General-Docs/`)

**Lab READMEs** must not contain:
- Cross-lab content (each lab README covers only its own lab)
- Architecture explanations (those belong in `README.md`)

---

## Documentation accuracy rule

Documentation must describe what is currently implemented, not what we hope will be implemented.

- Future or planned items must be clearly labeled as `planned` or `future`.
- Do not update the status table in `README.md` until the corresponding PR is merged.
- Do not mark a gate as completed in `QUALITY_GATE.md` until the corresponding PR is merged.

---

## Cross-linking over duplication

When two documents need to reference the same content, the secondary document links to the primary. It does not reproduce the content.

**Example:**
- `README.md` mentions the Docker lab with a one-line description and a link to `examples/docker-lab/README.md`.
- `examples/docker-lab/README.md` contains the full runbook.
- `General-Docs/QUALITY_GATE.md` references the gate milestone with a one-line status entry and evidence link.

---

## ARCHITECTURE.md and QUALITY_GATE.md scope

`ARCHITECTURE.md` covers:

```text
Full system architecture across all generations
Crate layout, mathematical model, gate progression summary
Causal Continuity Paradox and planned physarum-llm design
```

`QUALITY_GATE.md` covers:

```text
Current gate status (completed / in progress / planned)
Acceptance criteria and evidence links per gate
Known risks and gate advancement rules
```

Neither file covers detailed per-issue history — GitHub Issues and PRs are the authoritative record.

---

## PR documentation checklist

Every PR that touches documentation should verify:

- [ ] The change is in the correct primary file (per the ownership table above)
- [ ] No content is duplicated — cross-links are used instead
- [ ] Nothing is marked as implemented that is not yet merged
- [ ] Future/planned items are clearly labeled
- [ ] The root `README.md` remains a short front door (not a detailed runbook)

---

## GitHub Issues and PRs as the historical record

Detailed milestone tracking — who did what, when, what was validated, what the output was — lives in GitHub Issues and PR bodies and comments. This is the authoritative, searchable, permanent record.

`QUALITY_GATE.md` is a living gate status document, not an archive. `ARCHITECTURE.md` is the authoritative design reference.

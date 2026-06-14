# Gate N.0 — Secure Organism Continuity: Threat Model

**Status:** Design — intentionally non-detailed. Details are documented when they become programmable and testable (Gate N.1 onwards).
**Closes:** Issue #89
**Sequence:** Gate N.0 design → Gate N.1 implementation → … → Gate N.7 AWS lab

---

## Purpose

The physarum organism propagates, senses, reasons, and records lineage across multiple hosts. This document defines the security model that governs that organism: who it trusts, how it identifies itself, how it protects its memory, and what it is allowed to do.

Gate N.0 is not a spec. It captures principles, identifies threats, and establishes invariants that all future implementation gates must satisfy.

---

## What this document is not

- Not an implementation guide
- Not a protocol specification
- Not a cryptographic algorithm selection
- Not a key management runbook

Those belong in Gate N.1 through N.7, written when code exists and tests can validate.

---

## Organism state at this design point

The organism as of v0.5.0 is a self-propagating binary that:

- Scans, discovers, and colonizes lab hosts via SCP + SSH
- Reasons via LLM (policy-gated, lab-only)
- Records a cryptographically-naive lineage chain (`--lineage-b64`)
- Embeds its own Exploit-DB catalog and Nuclei templates
- Produces structured evidence (SensingResult, PatternFinding)

The lineage chain exists. It is not yet signed. The organism has no identity beyond the process that runs it.

Gate N.0 defines what comes next.

---

## Threat model

### Who we are defending against

| Threat actor | Scenario |
|---|---|
| Rogue hop | A colonized host fakes a lineage entry or reports false evidence |
| Duplicate propagation | Two organism instances claim the same organism_id |
| Forged lineage | An external process injects a hop record into the chain |
| Compromised relay | A node-to-node channel is intercepted and modified |
| LLM manipulation | Malicious host response steers the LLM toward unsafe actions |
| Operator error | `--server` port exposed on a non-isolated network |

### What we are NOT defending against (lab scope)

- Nation-state adversaries on the control network
- Physical compromise of the seed host
- Malicious Docker image supply chain
- Internet-facing deployment

The organism is a research prototype. The threat model is bounded to lab and controlled AWS environments. Gate N.6 and N.7 validate that the security model works in those scopes.

---

## Trust topology

```
             ┌──────────────────────────────────────────┐
             │  Organism boundary                        │
             │                                           │
  operator   │   seed (hop 0)                           │
  ──────────►│   └─ hop 1                               │
   port 8080 │      └─ hop 2                            │
  (--server) │         └─ hop 3                         │
             │                                           │
             │   identity:  Agent DNA (inherited)        │
             │   channel:   SSH / mTLS (Gate N.2)        │
             │   memory:    Lineage Ledger (signed)       │
             │   policy:    PolicyGate (local, inherited) │
             └──────────────────────────────────────────┘
```

The operator sees the organism from outside via `--server`. The organism's internal communication (hop to hop, hop to seed) is a separate trust zone.

---

## Pilar 1 — Identidade

The organism needs to know whether a node belongs to it.

**Core principle:** identity is inherited, not assigned. The seed generates an organism identity at startup. Every propagated hop receives a derived identity from its parent. A node without a valid inherited identity is not part of the organism.

**Key questions this pillar answers:**

- What makes a node a valid member of this organism run?
- How does a newly colonized host prove it was enrolled by a legitimate parent?
- What minimal identity capsule travels with the organism as it propagates?
- How is the seed's identity generated and trusted as the root?

**What we call it:** Agent DNA — a minimal identity + policy capsule that every hop carries and passes forward.

**Implementation:** Gate N.1

---

## Pilar 2 — Comunicação

Hops talk to each other and to the seed. Today this happens over plain SSH. That is acceptable for a lab prototype; it is not acceptable for a security-hardened organism.

**Core principle:** node-to-node communication must be mutually authenticated. Neither side should be able to impersonate the other. The channel must be encrypted.

**Key questions this pillar answers:**

- How do two hops authenticate each other before exchanging evidence or lineage?
- What is the scope boundary between TLS (node to operator API) and mTLS (node to node)?
- How does a hop authenticate a relay or coordinator it has never seen before?
- What happens when a hop cannot reach its parent — does it wait, act conservatively, or terminate?

**Scope separation:**

| Channel | Protocol | Direction |
|---|---|---|
| Operator browser → seed API | TLS (one-way) | read-only, lab network |
| Hop → seed (back-channel) | SSH callback today → mTLS (Gate N.2) | evidence + lineage relay |
| Hop → hop (propagation) | SSH today → mTLS (Gate N.2) | SCP delivery + lineage inheritance |

**Implementation:** Gate N.2

---

## Pilar 3 — Lineage

The lineage chain is the organism's memory. Today it is a base64-encoded struct that travels in a CLI argument. It records what happened, but nothing prevents tampering.

**Core principle:** every event appended to the lineage must be signed by the node that produced it. A lineage chain where any entry cannot be verified is a broken chain.

**Key questions this pillar answers:**

- How does each hop sign its contribution to the lineage?
- How does a downstream node verify the full chain it received before appending to it?
- What happens if a gap or tampered entry is detected?
- How are sensitive fields (credentials, internal IPs) kept out of the lineage?
- How does the lineage survive propagation without growing unboundedly?

**What we call it:** Lineage Ledger — a tamper-evident, append-only event chain with per-entry signatures.

**Implementation:** Gate N.3

---

## Pilar 4 — Política e Cortex

The organism can reason via LLM and act on that reasoning. This is the highest-risk surface in the entire stack. A misconfigured policy, a prompt injection on a target host, or a compromised LLM endpoint can all lead to out-of-scope action.

**Core principle:** the organism's ability to act is bounded by a policy capsule that it carries. The LLM proposes; the policy decides. No proposal from an external source can expand the policy.

**Two operating modes that the policy must account for:**

**Online Cortex Mode** — LLM endpoint reachable. Higher reasoning capability, but also higher exposure: the LLM receives evidence summaries, and its response must be validated before becoming action.

**Offline Cortex Capsule Mode** — No LLM path. The organism becomes more conservative: it falls back to heuristic scoring, avoids high-confidence exploitation, and queues events for later reconciliation. It does not stop — it narrows its action envelope.

**Key questions this pillar answers:**

- What actions are forbidden regardless of LLM confidence or operator mode?
- How does the policy capsule travel with the organism without being modified mid-chain?
- How does a hop verify it is receiving a policy from a legitimate parent and not a rogue host?
- When the LLM is unavailable, what is the minimum safe behavior?
- How are policy decisions recorded in the lineage without exposing sensitive fields?

**Implementation:** Gate N.4 (policy roots), Gate N.5 (Online/Offline Cortex secure mode)

---

## Security invariants

These rules must not be violated by any implementation in Gate N.1 through N.7.

1. **No identity, no colonization** — a node that cannot prove inherited identity from a valid parent must not colonize a new host.
2. **No unsigned lineage append** — a node may not append to the Lineage Ledger without signing its entry.
3. **No external policy expansion** — no response from an LLM, a remote host, or a relay may expand the action policy beyond what was inherited from the parent.
4. **Lab mode is explicit** — relaxed security (plain SSH, unsigned lineage, no mTLS) is only active when a build flag or runtime flag explicitly enables lab mode. It must not be the default.
5. **Lineage never carries secrets** — credentials, private keys, and internal topology details must not appear in lineage entries, even in encrypted form.
6. **Offline does not mean unrestricted** — loss of LLM access narrows the action envelope; it does not widen it.

---

## Back-channel and Gate N.2

The SSH callback back-channel (hop → seed, evidence relay, D_ij reinforcement) is part of this security model. It uses port 22, which is already open. The current implementation carries `callback_privkey + seed_ip` inside `PropagationLineage`.

Gate N.2 must:
- Replace the plain SSH callback with an mTLS-authenticated channel
- Bound what evidence a hop may relay (no raw credentials, no full filesystem paths)
- Define how D_ij reinforcement signals are validated before updating the graph

The current SSH callback is acceptable as a lab prototype. It is not acceptable as a production mechanism.

---

## Gate N sequence

| Gate | Scope | Depends on |
|---|---|---|
| N.0 | This document — threat model and invariants | — |
| N.1 | Agent DNA: identity capsule design and bootstrap | N.0 |
| N.2 | mTLS: node-to-node and hop-to-seed authenticated channel | N.1 |
| N.3 | Lineage Ledger: per-entry Ed25519 signatures and hash chain | N.1 |
| N.4 | Policy roots: signed capability manifest, inheritance model | N.1, N.3 |
| N.5 | Online/Offline Cortex secure mode behavior | N.4 |
| N.6 | Secure-mode Docker validation lab | N.2, N.3, N.4, N.5 |
| N.7 | Secure-mode AWS validation lab | N.6 |

Each gate opens with an implementation issue. Each gate closes with tests that validate its invariants. Details are written when code exists, not before.

---

## What comes after N.0

This document is complete when the PR is merged. The next step is Issue N.1: Agent DNA design and bootstrap implementation.

Issue #161 (WASM visualization) may proceed in parallel — it does not depend on Gate N security model.

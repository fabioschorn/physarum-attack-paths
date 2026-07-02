# Gate N.0 — Secure Organism Continuity: Threat Model

**Status:** Historical Gate N.0 design baseline, with current-state notes through v0.5.6.
**Closes:** Issue #89
**Sequence:** Gate N.0 design → Gate N.1 implementation → … → Gate N.7 AWS lab

> **Reading note:** this document was written against the v0.5.0 organism.
> Statements using “today” or “current” inside the original design sections refer
> to that design point. The table below records what changed afterward.

---

## Purpose

The physarum organism propagates, senses, reasons, and records lineage across multiple hosts. This document defines the security model that governs that organism: who it trusts, how it identifies itself, how it protects its memory, and what it is allowed to do.

Gate N.0 is not a protocol specification. It captures principles, identifies
threats, and establishes target invariants for the implementation gates.

## Implementation status after the design

| Area | State through v0.5.6 |
|---|---|
| Propagation-state confidentiality | AES-256-GCM implemented in Issue #187; plaintext legacy input and a plain JSON local save remain |
| Primary binary delivery | SCP-first delivery implemented in Issue #188; bounded HTTP fallback remains for OgnlExec recovery |
| Hop → seed reporting | mTLS implemented in Issue #189 with an ephemeral CA and issued client certificates |
| Operator dashboard | HTTPS available via `--tls` / `PHYSARUM_TLS=true` |
| Deterministic graph scoring | Issue #201 implemented `Q_ij -> q_ema -> D_ij`, bounded lineage-score modelling, and `GET /paths` in `physarum-maze` |
| Hop → hop propagation | Still SSH/SCP; full mutually authenticated organism channel is not complete |
| Agent DNA | Not implemented |
| Signed Lineage Ledger | Not implemented |
| Signed policy roots | Not implemented |
| Secure-mode Docker/AWS gates | Not completed |

Issue #189 therefore implements the hop-to-seed portion of Gate N.2, not the
entire N.2 node-to-node trust design.

---

## What this document is not

- Not an implementation guide
- Not a protocol specification
- Not a cryptographic algorithm selection
- Not a key management runbook

Those belong in Gate N.1 through N.7, written when code exists and tests can validate.

---

## Organism state at the v0.5.0 design point

The organism as of v0.5.0 is a self-propagating binary that:

- Scans, discovers, and colonizes lab hosts via SCP + SSH
- Reasons via LLM (policy-gated, lab-only)
- Records a cryptographically-naive lineage chain (`--lineage-b64`)
- Embeds a filtered Exploit-DB metadata catalog and Nuclei detection templates;
  Exploit-DB scripts are not embedded or executed
- Produces structured evidence (SensingResult, PatternFinding)

The lineage chain existed but was not signed. The organism had no identity beyond
the process that ran it. Encryption added later protects confidentiality but does
not provide the per-entry authenticity required by the proposed Lineage Ledger.

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

The current runtime and the Gate N target must be read separately. The first
diagram describes v0.5.6 behavior; the second describes the intended secure
architecture.

### v0.5.6 current runtime

```text
operator/browser -- HTTPS dashboard (typically 8443) --> seed

seed -- SSH/SCP: binary + encrypted propagation state --> hop 1 --> hop 2 ...

propagated hops -- preferred mTLS reports (typically 8444) --> seed
propagated hops -- legacy HTTP report when mTLS material is absent --> seed

local controls
  +-- PolicyGate evaluates LLM proposals before execution
  +-- AES-256-GCM protects newly generated propagation-state payloads
  +-- deterministic graph scoring and /paths expose bounded path selection
```

This runtime does not yet provide Agent DNA, signed lineage, signed policy
roots, or mutually authenticated hop-to-hop communication. Browser routes are
read-oriented, but the organism server also hosts report ingestion.

### Gate N target architecture

```text
operator
  |
  +-- authenticated operator API --> seed trust root

seed trust root
  +-- issues inherited Agent DNA
  +-- anchors signed policy roots
  +-- verifies the append-only Lineage Ledger
  |
  +-- mutually authenticated channel --> hop 1 --> hop 2 ...
                                      |
                                      +-- signed evidence and lineage entries

validation
  +-- secure-mode Docker gate
  +-- secure-mode AWS gate
```

The operator interface and internal organism channels are separate trust zones.
The target architecture requires each node to prove inherited membership,
authenticate its peers, verify policy ancestry, and validate lineage before
extending it.

---

## Pillar 1 — Identity

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

## Pillar 2 — Communication

At the v0.5.0 design point, hops talked to each other and to the seed through the
then-current SSH/HTTP mechanisms. In v0.5.6, propagation remains SSH/SCP while
hop-to-seed reporting prefers mTLS.

**Core principle:** node-to-node communication must be mutually authenticated. Neither side should be able to impersonate the other. The channel must be encrypted.

**Key questions this pillar answers:**

- How do two hops authenticate each other before exchanging evidence or lineage?
- What is the scope boundary between TLS (node to operator API) and mTLS (node to node)?
- How does a hop authenticate a relay or coordinator it has never seen before?
- What happens when a hop cannot reach its parent — does it wait, act conservatively, or terminate?

**Scope separation:**

| Channel | Protocol | Direction |
|---|---|---|
| Operator browser → seed API | TLS (one-way) | read-oriented dashboard routes, lab network |
| Hop → seed (back-channel) | mTLS implemented as the preferred channel | evidence + lineage relay |
| Hop → hop (propagation) | SSH/SCP remains current | binary delivery + lineage inheritance |

**Implementation:** Gate N.2

---

## Pillar 3 — Lineage

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

## Pillar 4 — Policy and Cortex

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

These are target invariants for the completed Gate N design. They are not all
guarantees of the v0.5.6 `lab-only` runtime. Known gaps are called out below.

1. **No identity, no colonization** — a node that cannot prove inherited identity from a valid parent must not colonize a new host.
2. **No unsigned lineage append** — a node may not append to the Lineage Ledger without signing its entry.
3. **No external policy expansion** — no response from an LLM, a remote host, or a relay may expand the action policy beyond what was inherited from the parent.
4. **Secure mode must be explicit and testable** — v0.5.6 exposes only the `lab-only` policy profile. A future secure profile must fail closed when its identity, lineage-signing, or channel requirements are unavailable.
5. **Future Lineage Ledger entries must minimize secrets** — v0.5.6 carries issued mTLS client material inside AES-GCM-encrypted propagation state. Gate N.3 must separate transport bootstrap material from the long-lived, auditable ledger.
6. **Offline does not mean unrestricted** — loss of LLM access narrows the action envelope; it does not widen it.

---

## Back-channel and Gate N.2

Issue #189 added an mTLS-authenticated hop-to-seed channel whenever the organism
server is active and ephemeral PKI initialization succeeds. The seed creates an
ephemeral CA and issues client material that is transported inside encrypted
propagation state. The legacy plain-HTTP reporting path remains available when
propagation state does not contain the mTLS material, and the browser server
still exposes the compatibility report route without client-certificate
authentication.

Work still required for full Gate N.2:

- mutually authenticated hop-to-hop communication rather than SSH/SCP alone;
- identity binding stronger than possession of an issued client certificate;
- replay and lifecycle rules for issued credentials;
- validation boundaries for evidence and `D_ij` reinforcement;
- fail-closed behavior for a future secure policy profile.

---

## Gate N sequence

| Gate | Scope | Depends on |
|---|---|---|
| N.0 | This document — threat model and invariants | — |
| N.1 | Agent DNA: identity capsule design and bootstrap | N.0 |
| N.2 | mTLS: node-to-node and hop-to-seed authenticated channel | N.1 — hop-to-seed subset implemented by Issue #189 |
| N.3 | Lineage Ledger: per-entry Ed25519 signatures and hash chain | N.1 + deterministic scoring completed by Issue #201 |
| N.4 | Policy roots: signed capability manifest, inheritance model | N.1, N.3 |
| N.5 | Online/Offline Cortex secure mode behavior | N.4 |
| N.6 | Secure-mode Docker validation lab | N.2, N.3, N.4, N.5 |
| N.7 | Secure-mode AWS validation lab | N.6 |

Each unfinished gate should open with an implementation issue and close with
tests that validate its invariants. Details are written when code exists, not
before.

---

## What comes after N.0

Gate N.0 is complete as a threat-model and design baseline. No dedicated
implementation issue is currently open for Gate N.1.

The remaining sequence is:

1. **Gate N.1 — Agent DNA:** define and implement seed-rooted membership and
   inherited node identity. This remains the first unfinished identity
   dependency.
2. **Gate N.2 — authenticated channels:** Issue #189 implemented the
   hop-to-seed mTLS subset. Mutually authenticated hop-to-hop communication,
   credential lifecycle, and fail-closed secure-mode behavior remain pending.
3. **Deterministic scoring prerequisite:** Issue #201 completed Phase 2
   `Q_ij -> q_ema -> D_ij` scoring, lineage-score formalization, and the
   `physarum-maze` `/paths` endpoint. The v0.5.6 release gate validated those
   values in the PF-6 Phase 2 real-LLM lab. Deterministic scores are now ready
   to become inputs to signed lineage facts.
4. **Gate N.3 — Lineage Ledger:** add per-entry signatures and hash-chain
   verification after identity and deterministic scoring foundations exist.
5. **Gates N.4 and N.5:** introduce signed policy roots and secure Online/Offline
   Cortex behavior.
6. **Gates N.6 and N.7:** validate the completed secure mode in Docker and owned
   AWS lab environments.

Completed visualization work such as Issue #161 is part of project history, not
the remaining Gate N sequence.

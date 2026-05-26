# physarum-llm — Phase 1 Design Review

**Status:** Pre-implementation design document — awaiting Manager review before any code  
**Branch:** `design/physarum-llm-contracts`  
**References:** Issue #106, Issue #106 comment (Owner/Manager alignment, ID 4539760650)  
**Author:** Dev Lead

This document captures the Dev Lead's reading of the north-star comment, the gaps identified
before contracts can be written, and specific questions that require Manager resolution before
Phase 1 can produce a verifiable design.

---

## 1. Understanding of the intended behavior

The organism reasoning loop, as understood from Issue #106 and the alignment comment:

```text
1. physarum-scanner runs against a discovered target — returns rich fingerprint
2. If SSH/SCP succeeds → existing behavior, unchanged
3. If SSH/SCP fails OR port 22 closed → check: --llm-endpoint configured?
      NO  → dead-end scoring (×0.05), existing behavior
      YES → build DiscoveryQuery → send to physarum-llm
4. physarum-llm sends DiscoveryQuery to LLM backend
5. LLM returns PropagationStrategy
6. Policy gate checks strategy before execution
7. If accepted → execute bootstrap → capture result
      success → colonize, update lineage, continue organism loop
      failure → feed result back to LLM → attempt again
8. Loop: max 6 attempts per target
9. Stop: success | NoPath | policy rejects all strategies | 6 attempts exhausted
10. Each attempt appended to lineage as structured evidence
```

---

## 2. Gaps and open questions — Manager resolution required

### Gap 1 — Policy rejection feedback loop (diagram logic error)

In the Mermaid diagram from the alignment comment:

```
M -- No --> N [Reject strategy and record reason]
N --> O {Attempts < 6?}
O -- Yes --> K [Send DiscoveryQuery to physarum-llm]
```

If the policy rejects a strategy and the same `DiscoveryQuery` is sent again without
modification, the LLM will produce the same rejected strategy. This is an infinite
rejection loop bounded only by the 6-attempt limit.

**Question for Manager:**
Should the rejected strategy and the rejection reason be appended to the `DiscoveryQuery`
before the next LLM call, so the LLM can propose a different method? If yes, `DiscoveryQuery`
needs a `rejected_strategies: Vec<RejectedStrategy>` field.

**Proposed resolution (for Manager approval):**

```
Policy rejects strategy
→ append { method, rejection_reason } to DiscoveryQuery.rejected_strategies
→ send updated DiscoveryQuery to LLM
→ LLM is now aware of what was rejected and why
→ LLM proposes a different strategy
```

---

### Gap 2 — Phase ordering: contracts reference scanner fields not yet implemented

The alignment comment defines `DiscoveryQuery` with fields that physarum-scanner does not
currently produce:

```
service_guess
banner_or_handshake_summary
version_hint
os_hint
confidence
```

Phase 2 (physarum-llm crate) is planned before Phase 3 (scanner enrichment). This means
Phase 2 will define a contract that Phase 3 must fulfil — but Phase 2 has no way to
validate that the scanner can actually produce those fields.

**Question for Manager:**
Should Phase 3 (scanner enrichment) be moved before Phase 2 (physarum-llm crate), or should
Phase 2 use stub/placeholder values for the enriched fields and treat them as mandatory after
Phase 3?

**Proposed resolution (for Manager approval):**
Run Phase 3 and Phase 2 in parallel or swap their order:
- Phase 2: physarum-scanner enrichment (extend `ScanResult` with new fields)
- Phase 3: physarum-llm crate types (built against the enriched `ScanResult`)

This ensures the contract is validated against real scanner output before the LLM client is built.

---

### Gap 3 — OS fingerprinting requires capabilities physarum-scanner does not have

The alignment comment lists `os_hint` as a required scanner output field. OS fingerprinting
requires one of:

```
TTL analysis via raw ICMP (requires CAP_NET_RAW or root)
TCP stack fingerprinting (ISN, window size, options — requires raw sockets)
nmap -O equivalent (requires root)
```

physarum-scanner currently performs TCP connect scanning only. It does not have raw socket
access in the maze propagation context (which runs as a non-root user on colonized nodes).

**Question for Manager:**
Should `os_hint` be:
a) best-effort only — derived from banner analysis (e.g. "Linux" from SSH banner, "Windows" from SMB),
   no raw socket requirement?
b) a hard requirement — raw sockets or CAP_NET_RAW added to the maze binary?
c) optional in Phase 3, deferred to a later gate?

This decision changes the physarum-scanner Cargo.toml dependencies and the maze binary
privilege model.

---

### Gap 4 — `required_artifact_type` is undefined

The alignment comment includes `required_artifact_type` in the recommended `PropagationStrategy`
response shape, but does not define what values are valid.

**Question for Manager:**
What is the type and value set for `required_artifact_type`? Proposal:

```rust
pub enum ArtifactType {
    Binary,       // physarum-maze ELF binary (current propagation model)
    Script,       // shell script only
    None,         // no artifact needed (e.g. pure HTTP exploit with in-memory execution)
}
```

Is this the right model, or should `required_artifact_type` be a free-form string? A free-form
string makes policy enforcement harder.

---

### Gap 5 — `bootstrap_plan` structure is underspecified

The alignment comment says the LLM output should be "structured and policy-checkable, not
free-form shell text only." But `bootstrap_plan` is not defined beyond its name.

**Question for Manager:**
What is the structure of `bootstrap_plan`? Two options:

**Option A — Typed steps:**
```rust
pub struct BootstrapPlan {
    pub steps: Vec<BootstrapStep>,
}

pub struct BootstrapStep {
    pub action:   BootstrapAction,   // enum: HttpPost, ShellCommand, CurlDownload, ...
    pub target:   String,
    pub payload:  String,
    pub timeout_ms: u64,
}
```

**Option B — Structured shell with metadata:**
```rust
pub struct BootstrapPlan {
    pub command:       String,      // shell command to execute
    pub requires_root: bool,
    pub side_effects:  Vec<String>, // e.g. ["writes to /tmp", "opens port 9000"]
    pub undo_command:  Option<String>,
}
```

Option A is safer (each step is policy-checkable individually). Option B is simpler for the
LLM to produce and for the organism to execute.

---

### Gap 6 — LLM prompt template is absent

The alignment comment specifies that the prompt must declare the lab context:

```
controlled pentest lab
owned/authorized environment
isolated test scope
not Internet scanning
not production execution
```

But no prompt template is defined. The quality of `PropagationStrategy` responses depends
heavily on the prompt. Without a fixed template, two implementations will produce incompatible
LLM behavior.

**Question for Manager:**
Should the prompt template be defined as part of Phase 1 design (alongside the data contracts),
or left to the Phase 2 implementation? Recommendation: define it in Phase 1 — it is part of the
contract between physarum-llm and the LLM backend.

**Proposed minimal template structure (for Manager review):**

```text
SYSTEM:
You are a security reasoning assistant operating inside a controlled pentest lab.
The lab environment is owned, isolated, and authorized for security research.
This is NOT Internet scanning. This is NOT production. Targets are owned lab VMs.

You will receive a DiscoveryQuery describing a target host and the organism's current state.
You must return a PropagationStrategy in the exact JSON schema provided.
If no safe propagation path exists, return method: "NoPath".
Only suggest methods from the allowed list: [SSH, HTTP, Custom].
Do not suggest methods outside the allowed list.
Confidence must be between 0.0 and 1.0.
Do not include secrets, credentials, or API keys in your response.

USER:
<DiscoveryQuery as JSON>
Expected response schema: <PropagationStrategy JSON schema>
```

---

### Gap 7 — Lineage fields for attempt evidence not defined

The alignment comment specifies that each attempt should append:

```
target
attempt_number
method_class
policy_decision
execution_result
reasoning_summary
next_action
```

But `lineage.rs` in physarum-maze currently has no field for this structure. The lineage
format needs to be extended before Phase 4 integration.

**Question for Manager:**
Should the lineage extension be defined in Phase 1 (as a contract) and implemented in Phase 4,
or is it acceptable to define it during Phase 4 when the maze integration is built?

Recommendation: define the schema in Phase 1, implement in Phase 4.

---

## 3. Items that are clear and ready for Phase 1

The following are unambiguous in the alignment comment and can be written immediately once
the gaps above are resolved:

```
LlmClient trait signature (async, returns PropagationStrategy)
DiscoveryQuery core fields (target, ports, lineage, methods_tried)
PropagationMethod variants (Ssh, Http, Exploit, Custom, NoPath)
Policy gate rules (CIDR check, method allowlist, confidence threshold, attempt count)
Disabled-by-default behavior (--llm-endpoint absent → no behavior change)
Max 6 attempts per target
API key never stored in lineage
```

---

## 4. Proposed revised phase order (for Manager approval)

Based on the gaps above, the Dev Lead proposes this revised sequence:

| Phase | Content | Blocker resolved |
|---|---|---|
| 1 | **Contracts only**: DiscoveryQuery, PropagationStrategy, LlmClient trait, prompt template, lineage extension schema, policy gate spec | Gaps 1–7 above |
| 2 | **physarum-scanner enrichment**: add service_guess, banner, version_hint, os_hint (best-effort) | Gap 2, Gap 3 |
| 3 | **physarum-llm crate**: types, OpenAiCompatibleClient, mock client, unit tests | Gap 4, Gap 5 |
| 4 | **physarum-maze integration**: CLI flags, decision loop hook, attempt loop, lineage update | Gap 6, Gap 7 |
| 5 | **Lab validation**: terraform-vuln, ansible-vuln, CVE-2021-41773 PoC | all above |

This differs from the alignment comment's phase order by moving scanner enrichment before
the crate implementation, and by making Phase 1 a pure design artifact (no Rust code).

---

## 5. Summary of Manager decisions needed

| # | Question | Blocking |
|---|---|---|
| 1 | Add `rejected_strategies` to DiscoveryQuery for policy feedback loop? | Phase 1 contract |
| 2 | Swap Phase 2/3 order (scanner before crate)? | Phase ordering |
| 3 | `os_hint`: best-effort banner-derived, raw socket, or deferred? | Phase 2 scope |
| 4 | `required_artifact_type`: typed enum or free-form string? | Phase 1 contract |
| 5 | `bootstrap_plan`: typed steps (Option A) or structured shell (Option B)? | Phase 1 contract |
| 6 | Prompt template: define in Phase 1 or Phase 3? | Phase 1 scope |
| 7 | Lineage extension schema: define in Phase 1 or Phase 4? | Phase 4 scope |

No implementation code will be written until these decisions are recorded.

---

## 6. Manager decisions — recorded 2026-05-26 (PR #109 comment)

All 7 gaps resolved. Dev Lead approved to proceed to Phase 1 contracts.

| # | Decision |
|---|---|
| 1 | **YES** — add `rejected_strategies: Vec<RejectedStrategy>` to `DiscoveryQuery`; every policy rejection fed back into next LLM query |
| 2 | **Revised order approved**: Phase 1 contracts → Phase 2 scanner enrichment → Phase 3 llm crate → Phase 4 maze integration → Phase 5 lab |
| 3 | **`os_hint: Option<OsHint>` — best-effort only**; derived from banners/handshakes; no raw sockets; no new CAP_NET_RAW/root requirement |
| 4 | **Typed enum**: `AgentBinary`, `Script`, `HttpRequest`, `None` — free-form strings not acceptable for policy enforcement |
| 5 | **Option A — typed steps**: `BootstrapPlan { steps: Vec<BootstrapStep> }`; `BootstrapAction` enum; free-form shell not the default |
| 6 | **Define prompt template in Phase 1** — it is part of the contract; must be deterministic for mock tests |
| 7 | **Define lineage schema in Phase 1; implement in Phase 4** — `LlmAttemptEvidence` struct defined now, wired in Phase 4 |

### Additional Manager constraints

- `Exploit` variant must be policy-disabled by default; requires explicit lab mode + CIDR + confidence + attempt rules
- Contracts should describe method classes and typed steps — not normalize the repo around raw exploit payload content
- Without `--llm-endpoint`: current physarum-maze behavior must remain **identical**
- With `--llm-endpoint`: LLM reasoning enabled only under explicit lab policy

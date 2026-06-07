# physarum-llm — Design Decisions and Current Contract State

**Status:** Implemented and Docker-validated through PF-6 Phase 1; Phase 2 execution validation active  
**References:** Issue #106, PRs #109/#110, PF-4, PF-5, PF-5.2, PR #140, Issue #141

---

## 1. Architectural role

`physarum-llm` provides provider-neutral contracts and clients for the reasoning layer used by `physarum-maze`.

It does not own execution authority.

```text
LLM proposes.
PolicyGate decides.
The executor performs typed, allowed actions.
Lineage records the result.
```

The crate supports an OpenAI-compatible client and deterministic mock paths for controlled tests.

---

## 2. Core decisions

The original design review established these constraints before implementation:

| Area | Decision |
|---|---|
| Policy rejection feedback | Rejected strategies return in later queries so blocked methods are not repeated blindly |
| Scanner evidence | Service, banner, version, protocol, and best-effort OS hints are structured fields |
| Artifact types | Closed typed enum rather than free-form strings |
| Bootstrap plan | Ordered typed steps rather than unrestricted shell by default |
| Prompt/schema | Versioned as part of the contract and covered by tests |
| Lineage | `LlmAttemptEvidence` records proposals, decisions, and execution outcomes |
| Exploit class | Disabled by default; requires explicit lab policy, CIDR, confidence, and attempt controls |
| Secrets | Raw credentials and private keys never enter strategy contracts or lineage |
| Custom execution | Disabled by default in the lab policy |

---

## 3. Current two-turn LLM flow

### Turn 1 — template selection

`physarum-maze` builds a template-selection request from observed evidence and compact template metadata.

Representative contract concepts:

```text
TemplateSelectionQuery
TemplateSelectionResponse
selected_template_ids
selection_reasoning
```

Input includes:

```text
- target address
- open ports
- protocol/service hints
- banner/version evidence
- compact template metadata
- allowed safety classes and filters
```

The LLM selects candidate template IDs. `physarum-sporangium` executes only templates that exist locally and pass the configured filters.

### Turn 2 — propagation reasoning

After template execution and vulnerability enrichment, `physarum-maze` builds `DiscoveryQuery`.

Current query context may include:

```text
- source_ip
- target evidence
- PatternFindingSummary
- vulnerability_candidates
- selected/executed template IDs
- prior rejected strategies
- lineage context
- ephemeral_pubkey when Phase 2 is enabled
```

The LLM returns a typed `PropagationStrategy` with an ordered `BootstrapPlan`.

---

## 4. Contract boundaries

### 4.1 Typed execution

The default contract uses typed actions and method classes. Free-form shell is not the normal execution surface.

The executor validates actions locally and resolves local capabilities and secrets at runtime.

### 4.2 PolicyGate

`PolicyGate` enforces:

```text
- target CIDR allowlist
- confidence threshold
- attempt limit
- allowed propagation method classes
- exploit_enabled boundary
- lab-only configuration
```

A strategy rejected by policy is stored as evidence and can be fed into the next reasoning attempt.

### 4.3 Secret handling

```text
- `LLM_API_KEY` is injected locally.
- API keys are never stored in lineage.
- The temporary SSH private key remains local to host-a.
- Only the temporary public key may appear in approved query/action context.
- Raw PEM, passwords, tokens, and private keys must not appear in prompts, strategies, logs committed as evidence, or lineage.
- Secret references are resolved locally by the executor.
```

---

## 5. Evidence integration

The current end-to-end data path is:

```text
SensingResult / PortScan
  -> TemplateSelectionQuery
  -> TemplateSelectionResponse
  -> physarum-sporangium template execution
  -> PatternFindingSummary
  -> VulnerabilityIntelService
  -> vulnerability_candidates
  -> DiscoveryQuery
  -> PropagationStrategy
  -> PolicyGate
  -> execution result
  -> LlmAttemptEvidence / lineage
```

HTTP and TCP findings are first-class evidence paths. The LLM does not receive fabricated findings to satisfy a lab expectation.

---

## 6. Current phase status

| Phase | Content | Status |
|---|---|---|
| 1 | Core contracts: `DiscoveryQuery`, `PropagationStrategy`, `LlmClient`, prompt/schema, `PolicyGate`, lineage evidence | Done |
| 2 | Scanner enrichment: service, banner, version, protocol, best-effort OS hints | Done |
| 3 | OpenAI-compatible client, mock client, parsing/schema tests | Done |
| 4 | `physarum-maze` CLI/integration, decision loop, lineage wiring | Done |
| 5 | PF-4 real LLM Docker validation | Done |
| 6 | PF-5 adaptive startup/runtime sensing | Done |
| 7 | PF-5.2 vulnerability-intelligence integration | Done |
| 8 | LLM Turn 1 template selection and Turn 2 propagation reasoning | Done |
| 9 | PF-6 Phase 1 multi-target evidence | Done via PR #140 |
| 10 | PF-6 Phase 2 ephemeral-key SCP and lineage continuation | Active — Issue #141 |
| 11 | Controlled AWS LLM Lab adaptation | Planned after #141 |

The earlier `terraform-vuln` / Apache 2.4.49 concept was an initial planning direction and is superseded by the current PF-6 multi-target Docker architecture.

---

## 7. PF-6 Phase 2 contract requirements

Issue #141 reuses the unchanged Phase 1 evidence path.

The expected typed sequence is:

```text
1. Real evidence selects a target and strategy.
2. PolicyGate accepts only when Phase 2 is explicitly enabled.
3. host-a generates a temporary SSH keypair locally.
4. The public key is exposed through approved typed context.
5. The private key remains local.
6. SCP transfers the current `__self__` binary.
7. SSH starts propagated mode.
8. The target continues lineage.
9. `colonized` is recorded only after execution success.
10. Temporary secret material is cleaned up.
```

No contract change may introduce a hardcoded IP, CVE, template ID, finding, policy result, or success state.

---

## 8. Provider behavior

The contract is provider-neutral. OpenAI-compatible endpoints may include hosted providers or controlled local endpoints.

Provider selection must not alter:

```text
- schema validation
- PolicyGate behavior
- secret handling
- lineage semantics
- typed execution boundaries
```

---

## 9. Testing expectations

Changes to `physarum-llm` should preserve:

```text
- deterministic schema tests
- mock-client tests
- rejection-feedback tests
- attempt-number semantics
- secret-serialization safeguards
- invalid strategy rejection
- compatibility with the current maze integration
```

Runtime evidence belongs in the relevant lab evidence files and GitHub Issues/PRs, not duplicated in this design document.
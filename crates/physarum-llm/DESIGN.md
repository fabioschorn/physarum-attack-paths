# physarum-llm — Design Decisions

**Status:** Decisions recorded — contracts implemented in this crate (Phase 1)
**References:** Issue #106, PR #109 (design review, closed as superseded), PR #110 (implementation)

---

## Manager decisions — recorded 2026-05-26

All 7 design gaps from the pre-implementation review were resolved before any code was written.

| # | Gap | Decision |
|---|---|---|
| 1 | Policy rejection feedback loop | **YES** — add `rejected_strategies: Vec<RejectedStrategy>` to `DiscoveryQuery`; every policy rejection fed back into the next LLM query so the LLM cannot re-propose a blocked method |
| 2 | Phase ordering: contracts reference scanner fields not yet implemented | **Revised order**: Phase 1 contracts → Phase 2 scanner enrichment → Phase 3 llm crate → Phase 4 maze integration → Phase 5 lab |
| 3 | `os_hint`: raw socket vs best-effort banner-derived | **`os_hint: Option<OsHint>` — best-effort only**; derived from banners and handshakes; no raw sockets; no new `CAP_NET_RAW` or root requirement added to the maze binary |
| 4 | `required_artifact_type`: typed enum vs free-form string | **Typed enum**: `AgentBinary`, `Script`, `HttpRequest`, `None` — free-form strings rejected because policy enforcement requires a closed type set |
| 5 | `bootstrap_plan` structure | **Typed steps (Option A)**: `BootstrapPlan { steps: Vec<BootstrapStep> }` with a `BootstrapAction` enum; free-form shell commands are not the default |
| 6 | Prompt template: Phase 1 or Phase 3 | **Define in Phase 1** — the prompt is part of the contract; it must be deterministic for mock tests |
| 7 | Lineage extension schema: Phase 1 or Phase 4 | **Define schema in Phase 1; implement in Phase 4** — `LlmAttemptEvidence` struct defined in `types.rs`, wired into lineage in Phase 4 |

---

## Additional Manager constraints

- `Exploit` variant is **policy-disabled by default**; requires explicit lab mode activation plus CIDR allowlist + confidence threshold + attempt limit checks
- Contracts describe method classes and typed steps — raw exploit payload content is not normalized through the contract layer
- **Without `--llm-endpoint`**: current physarum-maze propagation behavior must remain **identical** (no behavioral change)
- **With `--llm-endpoint`**: LLM reasoning is enabled only under explicit lab policy configuration (`PolicyGate::lab_default()` with CIDRs populated)
- `--llm-api-key` is **never stored in lineage JSON** — injected locally via `$LLM_API_KEY` at runtime
- **Secret reference model** (Manager review, 2026-05-29): raw key material (`ephemeral_private_key_pem`) was removed from `BootstrapAction::ScpPullFromSource`. Replaced with `secret_ref: SecretRef { key_id, source }`. The LLM requests a capability class; the executor resolves the secret locally at runtime. Raw PEM, credentials, or API tokens must not appear in any strategy contract or lineage record.
- **`Custom` disabled by default**: `PropagationMethodClass::Custom` is excluded from `PolicyGate::lab_default().allowed_methods`. Free-form shell is not the default; must be explicitly enabled in lab configuration.
- **Attempt numbering is one-based**: `attempt_number` in `DiscoveryQuery`, `RejectedStrategy`, and `LlmAttemptEvidence` counts from 1. `PolicyGate::evaluate()` rejects when `attempt_number > max_attempts` (attempt 6 is valid; attempt 7 is not).

---

## Phase roadmap

| Phase | Content | Status |
|---|---|---|
| 1 | **Contracts**: `DiscoveryQuery`, `PropagationStrategy`, `LlmClient` trait, prompt template, lineage schema, `PolicyGate` | Done — this crate |
| 2 | **physarum-scanner enrichment**: add `service_guess`, `banner`, `version_hint`, `os_hint` (best-effort) fields to scanner output | Pending |
| 3 | **physarum-llm crate implementation**: `OpenAiCompatibleClient`, `MockLlmClient`, schema parsing tests | Pending |
| 4 | **physarum-maze integration**: CLI flags (`--llm-endpoint`, `--llm-model`, `--llm-api-key`, `--llm-timeout-ms`), decision loop, lineage wiring | Pending |
| 5 | **Lab validation**: `terraform-vuln/` (Apache 2.4.49, port 80 only, SSH closed), CVE-2021-41773 PoC with reverse-pull propagation | Pending |

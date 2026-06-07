# PF-6 — End-to-End Multi-Target Docker Lab

> Historical note: this document originated as the two-container PF-6 design. The implemented lab now uses one organism container and two target containers.

**Status:** Phase 1 implemented and evidenced; Phase 2 active through Issue #141  
**Current topology:** `host-a` + `host-b` + `host-c`  
**Primary implementation PRs:** #139 and #140

---

## 1. Purpose

PF-6 validates the complete `physarum-maze` organism loop in Docker before adapting the same design to the controlled AWS Lab.

The lab must prove real dynamic behavior rather than a scripted success path:

```text
stimulus
  -> scan
  -> service/version evidence
  -> LLM Turn 1 template selection
  -> physarum-sporangium execution
  -> PatternFindingSummary
  -> VulnerabilityIntelService
  -> vulnerability_candidates
  -> LLM Turn 2 ordered strategy
  -> PolicyGate
  -> controlled execution
  -> lineage
```

No target IP, CVE, template, finding, policy result, or colonization result may be hardcoded into the organism control path.

---

## 2. Current topology

```text
External LLM endpoint
        |
        |  regular Docker network
        |
+-------+---------------------------------------------------+
| host-a — physarum-maze seed                              |
| - startup sensing                                        |
| - automatic interface selection                          |
| - physarum-scan / physarum-scanner                       |
| - LLM Turn 1                                             |
| - physarum-sporangium                                    |
| - VulnerabilityIntelService                              |
| - LLM Turn 2                                             |
| - PolicyGate                                             |
| - lineage                                                |
+-------+---------------------------------------------------+
        |
        |  isolated PF-6 internal network
        |
   +----+--------------------+
   |                         |
+--+------------------+  +---+-----------------------------+
| host-b              |  | host-c                          |
| Struts service path |  | ProFTPD / Wing FTP service path|
| SSH for Phase 2     |  | SSH for Phase 2                |
+---------------------+  +---------------------------------+
```

The two target containers are necessary to demonstrate that the organism is not tied to one service, one port, one CVE, or one protocol.

`host-b` and `host-c` remain isolated from the Internet. Only `host-a` receives the external network path needed for the configured LLM endpoint.

---

## 3. Container roles

### 3.1 host-a — organism controller

`host-a` runs `physarum-maze` in seed mode with:

```text
- startup sensing
- ICMP/TCP-eBPF stimulus support where applicable
- automatic interface selection from the allowed CIDR
- HTTP and TCP service probing
- builtin and nuclei-legacy template access
- real or mock OpenAI-compatible LLM support
- vulnerability intelligence
- PolicyGate
- lineage persistence
- temporary SSH key lifecycle for Phase 2
```

Representative environment variables:

```env
PHYSARUM_LLM_ENDPOINT=https://api.openai.com
PHYSARUM_LLM_MODEL=gpt-4o-mini
LLM_API_KEY=...
PHYSARUM_LLM_LOG_PROMPTS=true
PHYSARUM_VULN_INTEL_MODE=auto
PHYSARUM_VULN_INTEL_CACHE_DIR=/advisory-cache
PHYSARUM_TEMPLATE_DIR=/templates/nuclei-legacy
```

Representative runtime behavior:

```text
--mode seed
--interface auto
--llm-allowed-cidr <pf6-internal-cidr>
--discovery-interval-secs 5
--stimulus-timeout-secs 120
```

### 3.2 host-b — Struts path

`host-b` exposes the Struts path used by the PF-6 evidence design and an SSH service used only during the explicitly enabled Phase 2 propagation stage.

The Struts CVE is lab data, not a hardcoded organism decision.

### 3.3 host-c — FTP paths

`host-c` exposes the ProFTPD and Wing FTP service paths plus an SSH service for Phase 2.

This target exercises TCP/non-web evidence handling and prevents the lab from becoming a Struts-only demonstration.

---

## 4. Phase 1 — completed dynamic evidence loop

PF-6 Phase 1 was implemented through PR #140.

Required behavior:

```text
1. startup sensing begins without an external ping harness.
2. host-a selects the internal interface automatically.
3. host-b and host-c are discovered dynamically.
4. physarum-scan records open ports and service/banner/version hints.
5. LLM Turn 1 receives a compact template catalog.
6. Turn 1 selects applicable template IDs dynamically.
7. physarum-sporangium executes selected HTTP/TCP templates.
8. PatternFindingSummary is produced from observed responses.
9. VulnerabilityIntelService creates vulnerability_candidates.
10. LLM Turn 2 receives the enriched DiscoveryQuery.
11. Turn 2 returns an ordered typed strategy.
12. PolicyGate evaluates the strategy.
13. LlmAttemptEvidence and lineage record decisions, failures, and retries.
```

Baseline evidence:

```text
examples/evidence/pf6-tcp-probing-dualcve-phase1.json
```

Additional lineage evidence may exist under `examples/lab-evidence/`.

### 4.1 Phase 1 integrity rule

Phase 1 is the reference behavior for Docker and future AWS adaptation.

It must not be replaced by:

```text
- fixed target IPs in Rust logic
- fixed CVE results
- fixed template IDs
- injected findings
- forced vulnerability candidates
- bypassed LLM turns
- forced PolicyGate acceptance
- predeclared colonization success
```

Docker Compose may define the lab subnet and services. That configuration must not replace dynamic sensing and decision logic.

---

## 5. Phase 2 — active, Issue #141

Phase 2 does not redesign the organism. It extends the unchanged Phase 1 pipeline with the already-selected propagation mechanism.

### 5.1 Propagation sequence

```text
1. Phase 1 dynamically selects a target and strategy.
2. PolicyGate evaluates the strategy with Phase 2 explicitly enabled.
3. host-a generates a temporary SSH keypair.
4. Only the temporary public key is introduced on the selected target through the approved lab path.
5. The private key remains local to host-a.
6. The private key is never sent to the LLM or written to lineage.
7. SCP transfers the currently running `__self__` physarum-maze binary.
8. SSH starts the transferred binary in propagated mode.
9. The new node receives and continues the original lineage context.
10. `colonized` is recorded only after SCP, SSH, and propagated startup succeed.
11. Temporary key material is deleted after success, failure, timeout, or cleanup.
```

### 5.2 Required runner

Use the existing runner:

```bash
docker/pf6-lab.sh --phase2
```

Phase 2 remains opt-in.

### 5.3 Valid defect fixes

Implementation changes are allowed only for real defects found during execution, such as:

```text
- temporary key lifecycle
- public-key installation action
- SCP user/path/key arguments
- `__self__` resolution
- SSH command construction
- propagated-mode startup
- lineage handoff
- cleanup
```

Target-specific shortcuts are not valid fixes.

---

## 6. Phase 2 evidence

Preserve the Phase 1 evidence and create a separate Phase 2 artifact, for example:

```text
examples/evidence/pf6-phase2-ephemeral-key-scp-lineage.json
```

The evidence must show:

```text
- dynamically selected target
- observed ports and service hints
- Turn 1 selected template IDs
- templates actually executed
- PatternFindingSummary
- vulnerability candidate IDs and confidence
- Turn 2 reasoning summary
- ordered bootstrap actions
- PolicyGate Accepted with Phase 2 enabled
- temporary public-key path
- SCP result = Success
- SSH startup result = Success
- propagated-mode startup evidence
- lineage path/hop continuation
- `colonized` recorded after success
- temporary key cleanup
```

The evidence must not contain API keys, private keys, tokens, `.env.local` content, or raw secrets.

A marker file alone is not sufficient evidence of propagation.

---

## 7. Safety invariants

| Invariant | Enforcement |
|---|---|
| Docker-only until #141 completes | PF-6 scope |
| target containers have no Internet path | isolated internal network |
| LLM has no unrestricted shell authority | typed contracts and actions |
| exploit-class behavior disabled by default | `PolicyGate` configuration |
| Phase 2 explicitly enabled | opt-in runner/flags |
| target must be inside allowed CIDR | `PolicyGate` |
| private key remains local | local secret resolution |
| lineage contains no raw secrets | serialization contract and review |
| no hardcoded success path | code review and evidence comparison |
| cleanup is mandatory | runner and executor lifecycle |

---

## 8. Completion criteria

PF-6 Phase 2 is complete only when Issue #141 proves:

```text
- Phase 1 still behaves dynamically.
- host-b and host-c remain discoverable.
- Turn 1 and Turn 2 evidence is present.
- selected HTTP/TCP templates actually execute.
- PolicyGate accepts only under explicit Phase 2 policy.
- SCP transfers the current maze binary.
- SSH starts propagated mode.
- lineage continues on the target.
- colonization is recorded only after real success.
- temporary keys are removed.
- no hardcoded result was introduced.
```

After this gate, the same architecture and evidence contracts may be adapted to the controlled AWS Lab. AWS must not use a separate simplified implementation.

---

## 9. Authoritative references

```text
Issue #141
General-Docs/ARCHITECTURE.md
General-Docs/QUALITY_GATE.md
General-Docs/SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md
crates/physarum-llm/DESIGN.md
docker/docker-compose-pf6.yml
docker/pf6-lab.sh
```
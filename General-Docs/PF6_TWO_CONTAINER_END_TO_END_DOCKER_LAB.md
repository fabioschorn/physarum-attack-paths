# PF-6 — Two-Container End-to-End Docker Lab

**Issue:** #135  
**Status:** Design — pending implementation  
**Author:** Dev Lead (AI-assisted)  
**Date:** 2026-06-05

---

## 1. Purpose

PF-6 is the first end-to-end Docker Lab where `physarum-maze` operates against a **genuinely vulnerable container** (not a passive HTTP fixture). The goal is to prove that every skill absorbed by the organism — scan, spore enrichment, LLM reasoning, policy gate, lineage — fires dynamically without any hardcoded path, and that the organism can write evidence of contact onto the target volume.

The lab is structured in two phases:

| Phase | Gate condition | Scope |
|-------|---------------|-------|
| Phase 1 | Lineage proves full dynamic pipeline | Scan → Spore → VulnIntel → LLM → PolicyGate → lineage |
| Phase 2 | Container B volume receives a file | Replication discussion begins only after Phase 1 proof |

---

## 2. Lab Topology

Container A needs two network interfaces: one to reach Container B (isolated lab subnet), and one to reach the LLM API endpoint (external). Container B is **only** on the internal network — no Internet access.

```text
Internet / LLM API (api.openai.com or Ollama on host)
         │
         │  physarum-pf6-external (Docker bridge, no internal: true)
         │
┌────────┴────────────────────────────────┐
│ Container A — physarum-maze             │
│   eth0: DHCP        (external/LLM)     │
│   eth1: 172.21.0.2  (internal lab)    │
└────────┬────────────────────────────────┘
         │ sense / probe (eth1 — internal)
         │  physarum-pf6-internal (internal: true — no Internet)
         │
┌────────┴────────────────────────────────┐
│ Container B — vuln service              │
│   172.21.0.3  (internal lab only)      │
│   CVE RCE-capable target               │
│   volume: /tmp/physarum                │
└─────────────────────────────────────────┘
```

Port 22 is intentionally **not** exposed on Container B. Container A discovers it via the scan profile, not via SSH.

> **Why two networks:** `internal: true` on a Docker bridge disables all external routing for every container on that network. If Container A were only on the internal network, it could not reach the LLM API. The dual-network design isolates Container B from the Internet while leaving Container A's LLM path open.

---

## 3. Container A — physarum-maze

The organism image is `physarum-maze:lab` (cloud-built, nuclei-legacy baked in).

Capabilities required:
```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

Key environment variables:
```env
PHYSARUM_LLM_ENDPOINT=https://api.openai.com      # or mock-http for dry runs
PHYSARUM_LLM_MODEL=gpt-4o-mini
LLM_API_KEY=${LLM_API_KEY:-}
PHYSARUM_LLM_LOG_PROMPTS=true                      # required for Phase 1 evidence
PHYSARUM_VULN_INTEL_MODE=auto
PHYSARUM_VULN_INTEL_CACHE_DIR=/advisory-cache
PHYSARUM_TEMPLATE_DIR=/templates/nuclei-legacy
PHYSARUM_TEMPLATE_TAGS=rce,cve                     # narrow to relevant templates
PHYSARUM_TEMPLATE_SEVERITY=critical,high
```

Runtime command:
```bash
--mode seed
--interface eth1
--llm-endpoint ${PHYSARUM_LLM_ENDPOINT}
--llm-model ${PHYSARUM_LLM_MODEL}
--llm-allowed-cidr 172.21.0.0/24
--discovery-interval-secs 5
--stimulus-timeout-secs 120
```

Volumes:
```yaml
volumes:
  - ./lineage:/tmp          # lineage JSON written here
  - ../examples/advisory-cache:/advisory-cache:ro
```

---

## 4. Container B — Intentionally Vulnerable Service

### 4.1 Selection Criteria

The target service must:

1. Expose a version string in its HTTP `Server:` header or TCP banner (for `physarum-spore` to extract)
2. Have a known CVE with CVSS ≥ 7.0 mapped in `examples/advisory-cache/`
3. Be available as a pre-built Docker image (no custom build required)
4. Allow file writes to a mounted volume on successful exploitation path (Phase 2 gate)

### 4.2 Recommended Candidate — Apache Struts 2.5.25 (CVE-2021-31805)

```yaml
image: vulhub/struts2:2.5.25   # CVE-2021-31805, OGNL injection RCE (Struts 2.5.25 < 2.5.30 fix)
```

| Property | Value |
|----------|-------|
| CVE | CVE-2021-31805 |
| CVSS | 9.8 (Critical) |
| Mechanism | OGNL expression injection in HTTP `Content-Type` header |
| Server header | `Apache-Coyote/1.1` or `Apache Tomcat` |
| Port | 8080 |
| Phase 2 vector | POST to `/index.action` with OGNL payload writing to `/tmp/physarum/` |

### 4.3 Alternative — Log4Shell (CVE-2021-44228)

```yaml
image: vulhub/log4j:2.14.1-rce   # CVE-2021-44228, Critical
```

Log4Shell is widely documented and has a clear JNDI injection path. However, it requires a secondary LDAP callback server for full exploitation, which complicates the Phase 1 flow. Prefer Struts for the initial implementation.

### 4.4 Advisory Cache Entry Required

Before the lab runs, `examples/advisory-cache/` must contain an entry for the selected CVE:

```json
{
  "advisory_id": "CVE-2021-31805",
  "description": "Apache Struts OGNL injection via Content-Type header in multipart requests",
  "severity": "critical",
  "cvss_score": 9.8,
  "affected_service": "apache-struts",
  "ranges": [
    { "introduced": "2.0.0", "fixed": "2.5.30" }
  ],
  "cwe_ids": ["CWE-917"],
  "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31805"]
}
```

Volume configuration for Container B:
```yaml
volumes:
  - ./pf6-target-volume:/tmp/physarum  # Phase 2 gate — organism deposits evidence here
```

---

## 5. Phase 1 — Full Dynamic Pipeline Validation

### 5.1 What Must Fire (No Hardcoded Paths)

```text
startup-sensing
  ↓
physarum-scan: discovers 172.21.0.3:8080 (service_guess="http-alt")
  ↓
physarum-spore: runs matching templates against 172.21.0.3:8080
  - server-version-exposed template fires → extracted_facts["server"] = "Apache"
  - or content-type-header template fires → extracted_facts["framework"] = "struts"
  ↓
VulnerabilityIntelService: (service="apache-struts", version=detected)
  - LocalAdvisoryCache hit → CVE-2021-31805 (confidence 0.85)
  ↓
DiscoveryQuery: vulnerability_candidates = [CVE-2021-31805 (cvss=9.8, critical)]
  ↓
physarum-llm: LLM receives enriched query
  - reasoning_summary references CVE-2021-31805
  - proposes Http propagation on port 8080
  ↓
PolicyGate: Accepted (confidence ≥ 0.7 threshold)
  ↓
lineage: LlmAttemptEvidence recorded
  - stimulus_source = "startup-sensing"
  - cve_candidate_ids = ["CVE-2021-31805"]
  - strategy_confidence = 0.85
  - policy_decision = "Accepted"
```

### 5.2 Evidence Required for Phase 1 Completion

The lineage JSON must contain:
- `cve_candidate_ids` with `CVE-2021-31805` (or the selected CVE)
- `reasoning_summary` that references the CVE by ID or description
- `policy_decision = "Accepted"`
- `strategy_confidence ≥ 0.7`
- `stimulus_source = "startup-sensing"` (dynamic — not a manual trigger)

The committed evidence file will be:
```
examples/lab-evidence/physarum-lineage-pf6-phase1-docker-lab.json
```

### 5.3 PHYSARUM_LLM_LOG_PROMPTS Evidence

When `PHYSARUM_LLM_LOG_PROMPTS=true`, the full prompt and raw LLM response appear in container logs. The Phase 1 evidence commit must include:
- The lineage JSON
- A captured excerpt of the log showing the DiscoveryQuery and LLM response (operator IP masked as `<OPERATOR_IP>`)

---

## 6. Phase 2 — Container B Volume Write (Replication Discussion Gate)

Phase 2 does not begin until Phase 1 lineage is committed and validated by the Manager.

### 6.1 Gate Condition

Container B's volume (`./pf6-target-volume:/tmp/physarum`) must contain a file written by the organism after a successful propagation action. This proves that `physarum-maze` did not merely propose a path — it executed a verifiable interaction that left a trace on the target.

The file can be as simple as:
```
/tmp/physarum/physarum-contact-proof.txt
```

with content:
```text
physarum-maze contact: 2026-06-xx CVE-2021-31805 propagation attempt recorded
```

### 6.2 What Phase 2 Does NOT Include

- No exploit weaponization or payload execution beyond the minimal file write
- No exfiltration
- No lateral movement beyond the isolated 172.21.0.0/24 subnet
- Container B has no Internet access (internal network only)
- Lab is destroyed after evidence is committed

### 6.3 Phase 2 Leads to Replication Design

After the file write is confirmed, the Manager will define the replication model. The leading candidates at that point are:

| Model | Description |
|-------|-------------|
| SCP propagation | Organism copies itself to `/tmp/physarum/` on the target and executes |
| HTTP upload | Organism POSTs a payload via the confirmed RCE path |
| eBPF-guided | eBPF observer detects successful connection and triggers propagation routine |

The specific mechanism is a Manager decision, not a Dev Lead decision. This document does not pre-choose.

---

## 7. Security Invariants

These invariants apply to both phases and must be enforced at container runtime:

| Invariant | Enforcement |
|-----------|------------|
| `exploit_enabled=false` by default | `physarum-maze` PolicyGate flag |
| Container B has no Internet access | `physarum-pf6-internal` with `internal: true` — Container B on this network only |
| Container A can reach LLM API | Container A also on `physarum-pf6-external` (regular bridge) |
| `LLM_API_KEY` never in lineage | `llm_api_key` field stripped before lineage write |
| Operator IP masked | `<OPERATOR_IP>` in all committed files |
| Lab destroyed after evidence | `docker compose down -v` after commit |
| Container B volume is ephemeral | `./pf6-target-volume/` gitignored |

---

## 8. docker-compose-pf6.yml Skeleton

```yaml
# PF-6 two-container end-to-end lab (design skeleton — not yet implemented)
#
# Network design:
#   physarum-pf6-internal  — isolated bridge (internal: true)
#                            Container B is ONLY here: no Internet access
#                            Container A uses eth0 on this network to sense/probe B
#
#   physarum-pf6-external  — regular bridge (Internet access allowed)
#                            Container A uses eth1 on this network to reach the LLM API
#
# Container B cannot initiate connections to the Internet.
# Container A can call the LLM API via eth1 and still probe Container B via eth0.

networks:
  physarum-pf6-internal:
    driver: bridge
    internal: true     # Container B: no Internet
    ipam:
      config:
        - subnet: 172.21.0.0/24

  physarum-pf6-external:
    driver: bridge     # Container A: LLM API reachable here

services:
  host-b:
    image: vulhub/struts2:2.5.25
    container_name: physarum-pf6-target
    networks:
      physarum-pf6-internal:     # internal only — no Internet
        ipv4_address: 172.21.0.3
    volumes:
      - ./pf6-target-volume:/tmp/physarum

  host-a:
    image: physarum-maze:lab
    container_name: physarum-pf6-agent
    depends_on:
      - host-b
    networks:
      physarum-pf6-internal:     # eth0 — used to sense/probe Container B
        ipv4_address: 172.21.0.2
      physarum-pf6-external:     # eth1 — used to reach LLM API
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      RUST_LOG: "physarum_maze=debug,physarum_llm=debug,physarum_sporangium=info"
      LLM_API_KEY: "${LLM_API_KEY:-}"
      PHYSARUM_LLM_LOG_PROMPTS: "${PHYSARUM_LLM_LOG_PROMPTS:-false}"
      PHYSARUM_VULN_INTEL_MODE: "${PHYSARUM_VULN_INTEL_MODE:-auto}"
      PHYSARUM_VULN_INTEL_CACHE_DIR: "/advisory-cache"
      PHYSARUM_TEMPLATE_TAGS: "${PHYSARUM_TEMPLATE_TAGS:-rce,cve}"
      PHYSARUM_TEMPLATE_SEVERITY: "${PHYSARUM_TEMPLATE_SEVERITY:-critical,high}"
    command: >
      --mode seed
      --interface eth0
      --llm-endpoint ${PHYSARUM_LLM_ENDPOINT:-mock-http}
      --llm-model ${PHYSARUM_LLM_MODEL:-gpt-4o-mini}
      --llm-allowed-cidr 172.21.0.0/24
      --discovery-interval-secs 5
      --stimulus-timeout-secs 120
    volumes:
      - ./lineage:/tmp
      - ../examples/advisory-cache:/advisory-cache:ro
```

---

## 9. Implementation Order

1. Add advisory cache entry for selected CVE (CVE-2021-31805 or Manager-approved alternative)
2. Confirm nuclei-legacy contains a template matching the target service (tag: `struts`, `rce`, `cve`)
3. Wire `all_templates_with_yaml()` into the physarum-maze template runner (currently uses `all_templates()` — catalog.rs builtins only)
4. Create `docker/docker-compose-pf6.yml` from the skeleton above
5. Run Phase 1 lab — capture lineage and prompt logs
6. Commit evidence to `examples/lab-evidence/`
7. Get Manager approval before proceeding to Phase 2

Step 3 is the only code change required. Steps 1, 2, 4–7 are config and validation.

---

*End of document. Implementation begins after Manager review of this design.*

# physarum-attack-paths — Roadmap and Project State

Live reference for project status, lab inventory, evidence pipeline design, and planned evolution. The main `README.md` covers architecture, quick-start, and mathematical core.

---

## Safety and scope

This repository is a **controlled research prototype**. It is intended for owned, isolated, authorized labs only.

```text
Allowed scope:
  - local labs
  - Docker labs
  - owned AWS lab VPCs
  - controlled research environments

Not allowed:
  - public targets
  - Internet scanning
  - production deployment
  - unbounded propagation
  - unauthorized exploitation
```

LLM-assisted behavior is **lab-only**, policy-gated, and disabled unless explicitly configured. CVE-aware reasoning is treated as evidence and proposal generation, not automatic exploitation. `PolicyGate` remains the local decision boundary.

Secure identity, mTLS, signed lineage, and stronger trust controls are defined in Gate N.0 (`General-Docs/GATE_N0_THREAT_MODEL.md`). No production security guarantees are claimed before Gate N.1–N.7 are implemented.

---

## Current status

The current project focus is the `physarum-maze` organism path: LLM-driven template selection, dynamic vulnerability intelligence, multi-target evidence-driven propagation, and lineage-recorded policy decisions.

| Area | State |
|---|---|
| Rust workspace / protocol foundations | ✔ implemented |
| Adaptive graph scoring (`Q_ij`, `q_ema`, `D_ij`, `/paths`) | ✔ implemented and validated |
| Packet and flow observation (`physarum-ebpf`, packet observers) | ✔ implemented for lab research |
| Native scanner (`physarum-scan` / `physarum-scanner`) | ✔ implemented |
| Structured sensing (`SensingProfile`, `SensingResult`, `PortScan`) | ✔ implemented |
| Adaptive service classification | ✔ implemented |
| Nuclei-compatible native evidence engine (`physarum-spore` / `physarum-sporangium`) | ✔ complete Rust port — all protocols, matchers, extractors, generators |
| Nuclei-legacy template library (13,264 templates embedded in binary) | ✔ tar.zst via `include_bytes!` |
| Maze organism (`physarum-maze`) | ✔ primary active binary |
| LLM contracts and OpenAI-compatible client (`physarum-llm`) | ✔ implemented and Docker-validated |
| Real LLM Docker Lab | ✔ PF-4 validated |
| Adaptive startup/runtime sensing profiles | ✔ PF-5 / Issue #126 validated |
| Dynamic vulnerability intelligence (`VulnerabilityIntelService`: LocalAdvisoryCache + OsvFeed) | ✔ PF-5.2 — real LLM Docker Lab evidence committed |
| PF-6 Phase 1 — LLM two-turn selection, multi-target Docker Lab | ✔ complete — PR #140 |
| PF-6 Phase 2 — ephemeral-key SCP propagation, chain lineage | ✔ complete — PR #159 |
| Issue #144 — Exploit-DB enrichment + `OgnlExec` delivery, host-d validation | ✔ complete — PR #157 |
| Issue #158 — Propagation bug fixes: lineage-b64, musl binary, SSH-hang | ✔ complete — PR #159 |
| `physarum-maze` musl static binary (`x86_64-unknown-linux-musl`) | ✔ v0.4.0 |
| Gate N.0 — secure organism continuity threat model | ✔ design complete — PR #164 |
| `physarum-maze --server`: live organism graph API + Canvas HTML frontend (Issue #161) | ✔ complete — PR #170 / v0.5.0 |
| Inter-hop evidence relay and D_ij reinforcement via SSH back-channel | planned — before Gate N.2 |
| AWS Lab with real LLM | planned — after Gate N |

### Active binaries

```text
physarum-maze (x86_64-unknown-linux-gnu)   # organism runtime — local and CI use
physarum-maze (x86_64-unknown-linux-musl)  # static propagation binary — SCP'd to target hosts
physarum-scan                              # native scanner binary
physarum-spore                             # native pattern evidence binary
```

The musl variant carries no glibc dependency and runs on any Linux kernel, which is required when propagating into heterogeneous targets with unknown glibc versions.

---

## Evidence pipeline

The evidence pipeline is intentionally layered. Each stage produces structured output consumed by the next — no stage bypasses the one before it.

```text
 1. Startup or runtime stimulus (ICMP / TCP-eBPF / scheduled)
 2. Adaptive scanner profile (SensingProfile selection)
 3. Open ports, banners, service guesses, version hints (SensingResult)
 4. LLM Turn 1 — dynamic template selection (TemplateSelectionQuery)
 5. physarum-sporangium HTTP/TCP template execution
 6. PatternFindingSummary
 7. VulnerabilityIntelService → vulnerability_candidates  [first-class stage]
 8. DiscoveryQuery to LLM
 9. LLM Turn 2a — ordered propagation strategy proposal (PropagationStrategy)
10. [optional] LLM Turn 2b — enrichment: Exploit-DB lookup, OgnlExec delivery
11. PolicyGate decision
12. Controlled bootstrap execution (SshCommand, SCP __self__, OgnlExec …)
13. SCP musl binary → propagated agent starts on next hop
14. Lineage record (hop recorded, colonized flag, rejected_strategies carried forward)
```

### PF-5.2 — Dynamic vulnerability intelligence (complete)

Issue #131 (PR #132, #133) validated the CVE-aware enrichment pipeline as a first-class stage:

```text
service/version/banner evidence
  → physarum-spore extracts server version
  → VulnerabilityIntelService (LocalAdvisoryCache 0.85 / OsvFeed 0.75–0.50)
  → vulnerability_candidates in DiscoveryQuery
  → LLM references CVE in reasoning_summary
  → PolicyGate decision recorded in lineage
```

Evidence: `examples/lab-evidence/physarum-lineage-pf52-docker-lab.json` — real GPT-4o-mini run, CVE-2021-23017 matched for nginx/1.18.0.

### PF-6 Phase 1 (complete — PR #140)

Multi-target dynamic pipeline against genuinely vulnerable, dynamically discovered targets. Topology: host-a (seed) → host-b (Struts, CVE-2020-17530) + host-c (ProFTPD / Wing FTP).

No hardcoded paths: startup sensing discovers targets, LLM Turn 1 selects templates, sporangium executes, VulnerabilityIntelService enriches, LLM Turn 2 proposes, PolicyGate evaluates, lineage records. Evidence: `examples/evidence/pf6-tcp-probing-dualcve-phase1.json`.

### PF-6 Phase 2 (complete — PR #159)

End-to-end chain propagation via ephemeral-key SCP. Only the temporary public key appears in approved query context; the private key never leaves host-a and is never sent to the LLM or written to lineage. `colonized` recorded only after real, evidenced success.

Validated chain: `172.21.0.2 → .4 (hops=0) → .3 (hops=1) → .5 (hops=2)`. SSH sessions return under 600 ms via subshell nohup pattern (`(nohup ... </dev/null >log 2>&1 &)`). Evidence: `examples/evidence/pf6-phase2-ephemeral-key-scp-lineage.json`.

### Issue #144 — Exploit-DB enrichment and OgnlExec (complete — PR #157)

Exploit-DB CSV (~2 MB, zstd-compressed, embedded via `include_bytes!`) is parsed in memory at startup. The LLM autonomously queries it at enrichment time and generates an `OgnlExec.commands` array targeting host-d (CVE-2021-31805 / Struts 2.5.29) — no hardcoded payloads. `PolicyGate` validates each command element for shell metacharacter injection before execution.

---

## Labs

| Lab | What it validates | Status |
|---|---|---|
| `examples/local-lab` | Earlier coordinator/agent graph behavior | ✔ implemented |
| `examples/docker-lab` | Earlier A/B/C/D graph lab in Docker Compose | ✔ implemented |
| `docker/docker-compose-lab.yml` + `Utilities/docker-lab.sh` | physarum-maze adaptive sensing, mock/real LLM, lineage evidence | ✔ PF-4/PF-5 validated |
| `examples/pf-4-real-llm-lab` | Real LLM configuration and sensitive-info process | ✔ implemented |
| `examples/aws-lab/terraform` | EC2/VPC Mode 1/2, tc/netem, Gate K/K.1 | ✔ validated |
| `examples/aws-lab/terraform-pf1` | 7-node autonomous expansion maze | ✔ validated |
| `examples/aws-lab/terraform-pf2` | 9-node adaptive re-routing, TCP stimulus, secondary conduits | ✔ validated |
| `examples/lab-evidence/physarum-lineage-pf52-docker-lab.json` | PF-5.2 real LLM — CVE-2021-23017 enrichment, full pipeline | ✔ Issue #131 |
| `docker/docker-compose-pf6.yml` + `docker/pf6-lab.sh` | PF-6 Phase 1 — four-container lab, LLM two-turn, dual-CVE | ✔ complete — PR #140 |
| `docker/pf6-lab.sh --phase2` | PF-6 Phase 2 — chain propagation, ephemeral-key SCP, musl binary | ✔ complete — PR #159 |
| `docker/physarum-target-ognlexec.Dockerfile` (host-d) | Issue #144 — Exploit-DB + autonomous OgnlExec against Struts 2.5.29 | ✔ complete — PR #157 |
| `physarum-maze --server` + pf6-lab (Issue #161) | Live organism graph: axum SSE + Canvas HTML, depth rings, CVE badges, noise sensing nodes | ✔ complete — PR #170 / v0.5.0 |
| AWS LLM Lab | Real LLM in owned AWS VPC | planned — after Gate N |
| `formal/tla` | Formal models checked with TLC | ✔ implemented |

---

## Roadmap

| Phase / issue | Focus | State |
|---|---|---|
| Phase 0–2 | Protocol, coordinator, agents, local/Docker graph labs | ✔ done |
| Gate I–K | Flow observations, eBPF, adaptive path scoring | ✔ done |
| Gate L | Native scanner and TCP/ICMP stimulus sensing | ✔ done |
| Gate M | Runtime convergence and node consolidation | ✔ done |
| PF-1 | AWS organic expansion maze | ✔ done |
| PF-2 | AWS adaptive re-routing and secondary conduits | ✔ done |
| Issue #106 | DiscoveryQuery evidence loop and LLM-aware reasoning | ✔ done — PF-4/PF-5 |
| Issue #114 | Structured scanner sensing layer | ✔ done |
| Issue #115 | Native Nuclei-inspired evidence engine (`physarum-sporangium`) | ✔ done |
| Issue #126 | Adaptive sensing profiles for startup, ICMP, TCP/eBPF | ✔ done — PR #127 |
| Issue #131 | Dynamic vulnerability intelligence pipeline | ✔ done — PR #132, #133 |
| PF-6 Phase 1 | LLM two-turn selection, multi-target dynamic pipeline | ✔ done — PR #140 |
| PF-6 Phase 2 | Ephemeral-key SCP propagation, chain lineage, musl binary | ✔ done — PR #159 |
| Issue #144 | Exploit-DB enrichment + autonomous `OgnlExec` delivery | ✔ done — PR #157 |
| Issue #158 | Propagation bug fixes: lineage-b64, musl binary, SSH-hang | ✔ done — PR #159 |
| Issue #89 / Gate N.0 | Secure organism continuity threat model — design only | ✔ done — PR #164 |
| Issue #161 | `physarum-maze --server`: axum SSE API + Canvas HTML graph, embedded in binary | ✔ done — PR #170 / v0.5.0 |
| Back-channel | SSH callback: hop → seed, evidence relay, D_ij reinforcement (port 22 only) | planned — before Gate N.2 |
| Gate N.1 | Agent DNA: identity capsule design and bootstrap | planned — after Issue #161 |
| Gate N.2 | mTLS: node-to-node and hop-to-seed authenticated channel | planned |
| Gate N.3 | Lineage Ledger: per-entry Ed25519 signatures and hash chain | planned |
| Gate N.4–N.5 | Policy roots, Online/Offline Cortex secure mode | planned |
| Gate N.6–N.7 | Secure-mode Docker + AWS validation labs | planned |
| AWS LLM Lab | Real LLM in owned AWS VPC after Gate N | planned |

---

## Planned evolution

### v0.4.0 — what is complete

**PF-6 Phase 2 (PR #159)** — chain propagation through the four-container lab with ephemeral-key SCP, musl static binary, and subshell-nohup SSH fix. `colonized` recorded only after real, evidenced success.

**Issue #144 (PR #157)** — Exploit-DB CSV and Nuclei templates both self-contained in the binary via `include_bytes!`. LLM autonomously generates `OgnlExec.commands` targeting host-d. `PolicyGate` validates each command before execution.

**Issue #158 (PR #159)** — three propagation bugs fixed: `--lineage-b64` injection into `SshCommand`, musl static binary in Docker builder stage, SSH-hang root cause.

**Gate N.0 (PR #164)** — threat model document: 4-pillar security design (Identity, Communication, Lineage, Policy/Cortex), 6 security invariants, Gate N.1–N.7 sequence. Design only — no implementation code.

### v0.5.0 — Issue #161 (complete — PR #170)

`physarum-maze --server <PORT>` exposes a live organism graph API (axum + SSE) and serves a Canvas HTML frontend embedded in the binary via `include_str!`. The browser page shows each hop colonized in real time: seed node anchored at center, nodes positioned on depth rings, CVE badges on colonized hosts, noise nodes showing passive sensing activity, directed edges reflecting propagation order. Scrollable log panel with smart auto-scroll.

Wired into the PF-6 four-container lab (`./docker/pf6-lab.sh --phase2` → open `http://localhost:8080/`). Zero extra runtime files — same musl binary that propagates also serves the visualization.

**Bug fixes in this release:**
- Self-edge eliminated — `parent_ip` now captured before `lineage.extend()` mutates the path
- Seed node guaranteed at center — `NodeDiscovered{depth:0}` emitted on startup
- Exploit-DB enrichment policy updated — mandatory when `ExploitDb` capability available and CVE identified (no longer conditional on model uncertainty)

### Next — back-channel

### Pre-Gate N.2 — back-channel (next)

Each propagated hop calls back to the seed over SSH port 22 using an ephemeral callback keypair embedded in `lineage-b64`. The `ColonizationReport` updates D_ij on the seed and feeds the WASM live graph. No extra ports. Gate N.2 upgrades the transport to mTLS.

### Gate N.1–N.7

Full implementation sequence for secure organism continuity. Design captured in `General-Docs/GATE_N0_THREAT_MODEL.md`. Implementation starts after Issue #161 is complete.

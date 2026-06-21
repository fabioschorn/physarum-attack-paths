# physarum-attack-paths — Roadmap and Project State

Live reference for project status, lab inventory, evidence pipeline design, and planned evolution. The main `README.md` covers architecture, quick-start, and mathematical core.

**Current release:** v0.5.5

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

Secure identity, authenticated channels, signed lineage, and stronger trust controls are defined in Gate N.0 (`General-Docs/GATE_N0_THREAT_MODEL.md`). The v0.5.4 channel hardening is a substantial lab baseline, not completion of the full Gate N trust model. No production security guarantees are claimed before Gate N.1–N.7 are completed.

---

## Current status

The current project focus is the `physarum-maze` organism path: LLM-driven template selection, dynamic vulnerability intelligence, multi-target evidence-driven propagation, lineage-recorded policy decisions, and the v0.5.4 channel hardening stack (encrypted lineage, SCP-first delivery, mTLS back-channel, HTTPS browser dashboard).

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
| `physarum-maze` musl static binary (`x86_64-unknown-linux-musl`) | ✔ current release build — v0.5.5 |
| Gate N.0 — secure organism continuity threat model | ✔ design complete — PR #164 |
| `physarum-maze --server`: live organism graph API + Canvas HTML frontend (Issue #161) | ✔ complete — PR #170 / v0.5.0 |
| HTTP back-channel `POST /report-colonization` + Phase 1 D_ij emission (Issue #179) | ✔ complete — PR #181 |
| HTTP Basic Auth on browser-facing routes — `/`, `/graph`, `/events` (Issue #182) | ✔ complete — PR #182 |
| CI Docker smoke test — `physarum-maze-lab.Dockerfile` + runtime deps (Issue #183) | ✔ complete — PR #184 |
| D_ij edge animation — lerp conductivity, fungal palette, dead-end edges (Issue #174) | ✔ complete — PR #185 |
| Issue #187 — lineage-b64 AES-256-GCM encryption | ✔ complete — PR #192 / v0.5.4 |
| Issue #188 — SCP-first bootstrap delivery with bounded HTTP fallback for OgnlExec recovery | ✔ complete — PR #193 / v0.5.4 |
| Issue #189 / Gate N.2 subset — mTLS back-channel, ephemeral CA, per-agent client certs | ✔ complete — PR #194 / v0.5.4 |
| Issue #190 — HTTPS browser dashboard, ephemeral self-signed cert | ✔ complete — PR #195 / v0.5.4 |
| Issue #197 — release hygiene, rich build identity, structured help, policy-profile validation and release assets | ✔ complete — PRs #202–#207 / v0.5.5 |
| Back-channel via SSH — eliminate HTTP exposure on seed (Issue #186, documented) | roadmap — no date |
| Gate N.1 — Agent DNA: identity capsule design and bootstrap | planned — after Issue #187 |
| Gate N.3 — Lineage Ledger: per-entry Ed25519 signatures and hash chain | planned — after Gate N.2 |
| Gate N.4–N.7 — Policy roots, Online/Offline Cortex, secure-mode validation labs | planned |
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
14. mTLS back-channel: propagated agent reports colonization to seed (port+1)
15. Lineage record (hop recorded, colonized flag, rejected_strategies carried forward)
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

### Channel security stack (complete — v0.5.4, Issues #187–#190)

Four independent hardening items shipped as a single release milestone. See [`General-Docs/CHANNEL_SECURITY_DESIGN.md`](./CHANNEL_SECURITY_DESIGN.md) for full design rationale.

| Issue | What changed |
|---|---|
| #187 / PR #192 | Newly generated `--lineage-b64` payload encrypted with AES-256-GCM before base64; the per-run key is injected through the remote SSH bootstrap command/environment rather than the propagated agent's argument list |
| #188 / PR #193 | Propagated agents use SCP as the primary path; when SCP authentication fails and OgnlExec is available, a temporary HTTP server on the seed's lab-network IP serves the recovery bootstrap and is stopped after the attempt |
| #189 / PR #194 | Seed generates an ephemeral CA on startup; each propagated agent receives a unique client cert (AES-GCM lineage); back-channel port (`server+1`) requires a valid client cert; validated 3/3 in Docker lab |
| #190 / PR #195 | `--tls` / `PHYSARUM_TLS=true` enables HTTPS dashboard on port 8443; browser cert and mTLS cert both carry `DistinguishedName` CN/O = "Physarum Attack Path"; CA PEM exported to `/tmp/physarum/ca.pem` |

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
| `docker/pf6-lab.sh --phase2` | PF-6 Phase 2 — chain propagation, ephemeral-key SCP, musl binary, mTLS back-channel, HTTPS dashboard | ✔ complete — v0.5.4 |
| `docker/physarum-target-ognlexec.Dockerfile` (host-d) | Issue #144 — Exploit-DB + autonomous OgnlExec against Struts 2.5.29 | ✔ complete — PR #157 |
| `examples/server-graph-lab` + pf6-lab (Issue #161) | Live organism graph: axum SSE + Canvas HTML, depth rings, CVE badges, noise sensing nodes | ✔ complete — PR #170 / v0.5.0 |
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
| Issue #179 | HTTP back-channel `POST /report-colonization` + Phase 1 D_ij emission | ✔ done — PR #181 |
| Issue #174 | D_ij edge animation — lerp conductivity, fungal palette, dead-end edges | ✔ done — PR #185 |
| Issue #187 | lineage-b64 → AES-256-GCM — encrypt payload, close ps-aux OPSEC leak | ✔ done — PR #192 / v0.5.4 |
| Issue #188 | SCP-first bootstrap delivery with bounded HTTP fallback for OgnlExec recovery | ✔ done — PR #193 / v0.5.4 |
| Issue #189 / Gate N.2 subset | mTLS authenticated hop-to-seed reporting channel | ✔ done — PR #194 / v0.5.4 |
| Issue #190 | HTTPS browser dashboard — ephemeral self-signed cert, `Physarum Attack Path` DN | ✔ done — PR #195 / v0.5.4 |
| Issue #197 | Release hygiene: rich `--version`, structured `--help`, policy validation and release workflow/assets | ✔ done — PRs #202–#207 / v0.5.5 |
| Back-channel via SSH (#186) | Replace HTTP `/report-colonization` with SSH exec — seed exposes port 22 only | no date — see section below |
| Gate N.1 | Agent DNA: identity capsule design and bootstrap | planned — after Issue #187 |
| Gate N.3 | Lineage Ledger: per-entry Ed25519 signatures and hash chain | planned — after Gate N.2 |
| Gate N.4–N.5 | Policy roots, Online/Offline Cortex secure mode | planned |
| Gate N.6–N.7 | Secure-mode Docker + AWS validation labs | planned |
| AWS LLM Lab | Real LLM in owned AWS VPC after Gate N | planned |
| LLM template generation + RAG corpus | LLM auto-generates Nuclei templates for CVEs with no existing template; colonization outcome as ground truth; validated templates seed a RAG corpus for few-shot generation | future — after Gate N |

---

## Planned evolution

### v0.4.0 — what is complete

**PF-6 Phase 2 (PR #159)** — chain propagation through the four-container lab with ephemeral-key SCP, musl static binary, and subshell-nohup SSH fix. `colonized` recorded only after real, evidenced success.

**Issue #144 (PR #157)** — Exploit-DB CSV and Nuclei templates both self-contained in the binary via `include_bytes!`. LLM autonomously generates `OgnlExec.commands` targeting host-d. `PolicyGate` validates each command before execution.

**Issue #158 (PR #159)** — three propagation bugs fixed: `--lineage-b64` injection into `SshCommand`, musl static binary in Docker builder stage, SSH-hang root cause.

**Gate N.0 (PR #164)** — threat model document: 4-pillar security design (Identity, Communication, Lineage, Policy/Cortex), 6 security invariants, Gate N.1–N.7 sequence. Design only — no implementation code.

### v0.5.0 — Issue #161 + PRs #181 #182 #184 #185 (complete)

`physarum-maze --server <PORT>` exposes a live organism graph API (axum + SSE) and serves a Canvas HTML frontend embedded in the binary via `include_str!`. The browser page shows each hop colonized in real time: seed node anchored at center, nodes positioned on depth rings, CVE badges on colonized hosts, noise nodes showing passive sensing activity, directed edges reflecting propagation order. Scrollable log panel with smart auto-scroll.

Wired into the PF-6 four-container lab (`./docker/pf6-lab.sh --phase2`). Zero extra runtime files — same musl binary that propagates also serves the visualization.

**Additional v0.5.0 items:**
- **Issue #179 / PR #181** — HTTP back-channel `POST /report-colonization`: propagated agents report colonization to seed; Phase 1 D_ij emission (`conductivity = LLM confidence`) wired from agent.rs
- **PR #182** — HTTP Basic Auth middleware on browser routes (`/`, `/graph`, `/events`); `/report-colonization` intentionally unprotected (internal organism channel)
- **Issue #183 / PR #184** — CI Docker smoke test using `physarum-maze-lab.Dockerfile` (~60 s with cache); catches ENTRYPOINT and runtime dep regressions
- **Issue #174 / PR #185** — D_ij edge animation: `targetConductivity` + lerp in `layoutStep()` (~2 s transition at 60 fps); dead-end edges emitted at conductivity 0.05

**Bug fixes in this release:**
- Self-edge eliminated — `parent_ip` now captured before `lineage.extend()` mutates the path
- Seed node guaranteed at center — `NodeDiscovered{depth:0}` emitted on startup
- Exploit-DB enrichment policy updated — mandatory when `ExploitDb` capability available and CVE identified

### v0.5.4 — channel security stack (Issues #187–#190, complete)

Four independent hardening items that close the main OPSEC exposure vectors before Gate N implementation begins. See [`General-Docs/CHANNEL_SECURITY_DESIGN.md`](./CHANNEL_SECURITY_DESIGN.md) for full design.

**Issue #187 / PR #192 — AES-256-GCM lineage encryption:**
Newly generated `--lineage-b64` payloads are encrypted with AES-256-GCM. The
key is generated once per seed run and injected through the remote SSH bootstrap
command/environment rather than the propagated agent's argument list. This
hides the full lineage content from the propagated process argv, but a privileged
observer may still see bootstrap material while SSH is running. Legacy plaintext
base64 input and the plain JSON lineage save remain compatibility limitations.

**Issue #188 / PR #193 — SCP-first bootstrap delivery:**
Propagated agents use SCP after pubkey injection by the CVE exploit. When SCP authentication fails and an OgnlExec step is available, the seed starts a temporary HTTP server on its lab-network IP at port `:8001`, serves the recovery bootstrap, retries SCP, and then stops the server. The normal path stays inside SSH; the fallback remains a deliberately bounded lab mechanism.

**Issue #189 / PR #194 — mTLS back-channel:**
Seed generates an ephemeral CA on startup. Each propagated agent receives a unique TLS client cert (embedded in the AES-GCM encrypted lineage) before deployment. The back-channel port (`server_port + 1`) uses `WebPkiClientVerifier` — no cert, no report. Validated 3/3 back-channel reports in the Docker lab (`.4` depth=1, `.3` depth=2, `.5` depth=3).

The browser server still carries the legacy report route without client
certificate authentication. Current propagated agents prefer the dedicated
mTLS port when issued PKI material is present; removing or authenticating the
compatibility route is still pending.

**Issue #190 / PR #195 — HTTPS browser dashboard:**
`--tls` / `PHYSARUM_TLS=true` switches the dashboard to HTTPS (default port 8443). Seed issues a browser cert (SAN=`localhost` + `127.0.0.1`) signed by the same ephemeral CA. All three certs (CA, browser, mTLS back-channel) carry `DistinguishedName` CN/O = **Physarum Attack Path**. CA PEM exported to `/tmp/physarum/ca.pem` for optional trust import. Server binds `0.0.0.0` so Docker port-forwarding works. `pf6-lab.sh --phase2` now opens `https://localhost:8443/` automatically.

---

### v0.5.5 — release identity and operator-facing contract (Issue #197, complete)

The v0.5.5 release turns build provenance, CLI guidance, policy constraints, and
release artifacts into an explicit operator-facing contract:

- rich `physarum-maze --version` output with commit/build identity and policy profile;
- structured `--help` grouped by operational concern;
- validated `lab-only` policy profile and configurable `--llm-allowed-cidr`;
- release notes and GitHub-displayed SHA-256 digests for published assets;
- release supersession policy and clearer documentation of historical releases.

Artifact signing remains a future supply-chain improvement; the release workflow
does not publish a signed checksum manifest. GitHub displays a SHA-256 digest for
each uploaded asset, but independent cryptographic signatures are not yet
available.

---

## Back-channel via SSH — Issue #186 (no implementation date)

> **Motivation:** the current back-channel (`POST /report-colonization`) requires
> a dedicated HTTP/mTLS listener in addition to SSH. If the seed runs in an
> environment where only SSH is allowed — restricted AWS Security Group,
> hardened host, corporate firewall — no `ColonizationReport` reaches the seed.
> The graph then becomes blind to downstream colonizations.

### Current state

```
propagated (.4/.3/.5)  ──mTLS POST https://seed:8444/report-colonization──▶ seed
browser               ──HTTPS GET https://seed:8443/events──────────────▶ seed

Typical Phase 2 ports on seed: 22 (SSH) + 8443 (HTTPS dashboard) + 8444 (mTLS reports)
```

### Proposed architecture

Replace the HTTP back-channel with **SSH exec** against the seed. When a propagated agent colonizes a downstream host, it opens an SSH session to the seed and invokes an ingestion subcommand:

```
ssh seed_ip -i callback_key "physarum-maze --ingest-report '<json>'"
```

The seed registers `callback_key.pub` in its own `authorized_keys` before launching the agent — the same mechanism already used to colonize targets, only inverted. The HTTP server then listens on `127.0.0.1` only; the browser connects via tunnel:

```
ssh -L 8080:localhost:8080 seed_ip
open http://localhost:8080/
```

```
propagated (.4/.3/.5)  ──SSH exec──────────────────────────▶  seed:22
browser               ──SSH tunnel + HTTP 127.0.0.1──────▶  seed:22
seed:22  ─────────────────────────────────────────────────▶  target:22  (propagation, unchanged)

Port exposed on seed: port 22 only
```

### Why there is no implementation date

- Requires keypair flow redesign: the seed must generate and authorize a keypair to **receive** connections from propagated agents, in addition to the ephemeral key already used to **initiate** connections to targets
- The `--ingest-report` subcommand must validate the payload against injection — the propagated host is compromised and not trusted
- Migrating to `127.0.0.1` breaks the current Docker lab (external browser would need a tunnel or proxy; `docker-compose` port mapping would need to be redesigned)
- Fits more naturally as an evolution after Gate N.2 (mTLS) is defined — both address the same problem from different angles; the decision between them should be conscious

### Value for the project

| Dimension | Impact |
|---|---|
| OPSEC | Seed with minimal surface — only port 22 visible on the network |
| Resilience | Works in environments that block all ports except SSH |
| Coherence | The organism uses SSH to propagate *and* to report — single protocol, no mixed stack |
| Channel security | SSH is already encrypted and authenticated — resolves back-channel plaintext without additional PKI |
| Alignment with Gate N.2 | Can replace or complement mTLS depending on the design decision |

---

## Gate N.1–N.7

Full implementation sequence for secure organism continuity. Design captured in `General-Docs/GATE_N0_THREAT_MODEL.md`. Implementation starts after the channel security stack (v0.5.4) is complete.

---

## Future — LLM template generation + RAG corpus (post-Gate N)

When Exploit-DB identifies a CVE with no matching Nuclei template, the agent is blind — sporangium has nothing to run. The long-term direction is to close this gap generically, without manually curating templates for every future lab.

**Proposed loop:**

```text
Exploit-DB entry found → no template in catalog for this CVE
  → LLM receives: Nuclei YAML schema + Exploit-DB entry + N similar validated templates (RAG)
  → LLM generates a candidate Nuclei YAML template
  → physarum-sporangium executes the generated template against the target
  → If Phase 2 colonization succeeds (ground truth = real access):
      → Template persisted in catalog with confidence score
      → Triplet (Exploit-DB entry, generated template, outcome) appended to RAG corpus
  → Next host with similar CVE:
      → RAG retrieves N most similar validated templates
      → LLM uses them as few-shot examples → progressively more accurate generation
```

**Key design constraints:**
- Sporangium runs existing templates first — LLM generation only triggers for confirmed CVEs with no matching template
- Ground truth is Phase 2 success, not sporangium matcher alone (false positive in detection ≠ real access)
- RAG corpus grows from validated triplets only — no untested templates enter the few-shot pool
- YAML schema must be in the LLM context — Nuclei YAML structure is rigid (matchers, extractors, path templates)

**Relation to existing work:** Issue #144 validated that the LLM can autonomously generate `OgnlExec.commands` from Exploit-DB metadata. This extends the same pattern from command generation to full template generation. Gate N mTLS provides the trust foundation before extending the agent's generative surface.

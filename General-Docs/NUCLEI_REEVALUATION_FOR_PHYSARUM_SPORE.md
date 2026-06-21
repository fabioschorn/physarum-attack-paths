# Nuclei Re-evaluation for physarum-sporangium

**Document scope:** Formal 13-point feature comparison between ProjectDiscovery Nuclei (Go) and `physarum-sporangium` (Rust), justifying the architectural decision to build a native Rust detection engine rather than embed or call Nuclei.

**Date:** 2026-06-01  
**Related PR:** #132 (Issue #131 — dynamic vulnerability intelligence pipeline)  
**Author:** Dev Lead (AI-assisted analysis)

---

## 1. Background

When Issue #131 was scoped, the Manager requested a 13-point comparison of Nuclei vs. physarum-sporangium to establish whether Nuclei could serve as the detection layer for `physarum-maze` or whether the native Rust implementation was justified. This document records that analysis as a persistent architectural reference.

---

## 2. Comparison Matrix

| # | Feature | Nuclei (Go) | physarum-sporangium (Rust) | Decision |
|---|---------|-------------|---------------------------|----------|
| 1 | **HTTP protocol runner** | ✅ Full (methods, redirects, raw requests, race mode) | ✅ GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH + redirect policy | **Ported** |
| 2 | **Matchers: word, regex, status** | ✅ | ✅ | **Ported** |
| 3 | **Matchers: DSL** | ✅ govaluate-based boolean expressions | ✅ evalexpr-based with 20+ helper functions | **Ported** |
| 4 | **Matchers: binary (hex)** | ✅ | ✅ | **Ported** |
| 5 | **Matchers: size** | ✅ | ✅ | **Ported** |
| 6 | **Matchers: XPath** | ✅ antchfx/htmlquery + antchfx/xmlquery | ✅ scraper (HTML) + sxd-xpath (XML) | **Ported** |
| 7 | **Extractors: regex, kval, json** | ✅ | ✅ | **Ported** |
| 8 | **Extractors: XPath, DSL** | ✅ | ✅ | **Ported** |
| 9 | **CVE/CVSS in template metadata** | ✅ `info.cve-id`, `info.cvss-score` | ✅ `TemplateInfo.cve_id`, `cvss_score` — advisory layer enriches at runtime | **Architecture difference** (see §3) |
| 10 | **Service-keyed template selection (Wappalyzer)** | ✅ automatic tech fingerprint → template routing | ✅ advisory-cache keyed by service name; banner extractor feeds the key | **Architecture difference** (see §3) |
| 11 | **Multi-protocol (TCP/DNS/SSL/WebSocket)** | ✅ | ✅ (added in PR #133) | **Ported** |
| 12 | **Workflows / multi-step** | ✅ | ✅ workflow.rs engine | **Ported** |
| 13 | **External YAML template loading from disk** | ✅ | ✅ catalog.rs + YAML loader (configured directory; execution remains allowlisted) | **Ported** |

**Nuclei features deliberately out of scope for physarum-sporangium:**

| Feature | Reason excluded |
|---------|----------------|
| JavaScript / headless browser | Requires V8 runtime; not usable in a statically linked no_std-like maze agent |
| Interactsh (OOB callbacks) | External SaaS dependency; incompatible with offline-lab operation |
| Fuzzing engine | Broader attack surface, outside detection scope |
| Nuclei template signing/verification | Upstream signing is not used for the imported internal snapshot; GitHub displays release-asset digests, while artifact/template signing remains future supply-chain work |
| Nuclei Cloud / Team features | SaaS; irrelevant for self-contained organism |
| Burp / OpenAPI / Swagger input formats | Not needed; maze targets are discovered dynamically |
| Reporting exporters (Jira, ES, SARIF, PDF) | Lineage JSON covers our audit trail |

---

## 3. Architectural Differences

### 3.1 CVE/CVSS Metadata — Advisory Layer vs. Template Metadata

**Nuclei approach:** CVE identifiers and CVSS scores are embedded directly in individual template YAML files. Each template is purpose-built to detect one CVE.

**physarum-sporangium approach:** Templates are generic detection patterns (e.g. "nginx version banner extractor"). CVE enrichment happens in a separate advisory layer (`VulnerabilityIntelService`) that maps `(service, version)` → `Vec<VulnerabilityCandidate>` via structured advisory cache files and the OSV API.

**Why this is better for the organism:**
- A single "nginx version detect" template feeds all nginx CVEs simultaneously without requiring N separate template files.
- The advisory cache can be updated without touching template logic.
- The LLM reasoning loop receives rich, structured CVE data rather than opaque template IDs.
- New CVEs are covered by adding an advisory cache entry, not by deploying a new template.

### 3.2 Service-Keyed Template Selection

**Nuclei approach:** Uses Wappalyzer-style fingerprinting to automatically select templates relevant to the detected technology stack.

**physarum-sporangium approach:** The sporangium banner extractor pulls `Server:` header and SSH version strings into `PatternFinding.extracted_facts`. The `VulnerabilityIntelService` uses the extracted `(service, version)` tuple as the advisory cache key — achieving the same result without a separate fingerprinting database.

---

## 4. Embedding vs. Native Port Decision

### Option A — Embed Nuclei binary (rejected)

Calling a Go binary from a Rust async agent introduces:
- Cross-process IPC overhead (JSON stdout pipe)
- Go runtime in the container alongside Rust runtime
- No type safety at the Rust/Go boundary
- Cannot use `cargo` for supply-chain verification
- Nuclei template execution surface (arbitrary YAML → network) incompatible with physarum-maze's allowlist + PolicyGate model

### Option B — Nuclei as a library via FFI (rejected)

Nuclei does not expose a stable C ABI. `cgo` + `unsafe` FFI from Rust is high-maintenance and blocks `cross`-compilation for target architectures.

### Option C — Native Rust port (chosen)

- Full type safety, async-native, no runtime overhead
- Single `cargo build` with workspace-level audit
- Template execution is bounded by `RunPolicy::allowed_check_ids` and the
  PolicyGate. An operator may configure an external template directory, but
  loading a template does not by itself authorize its execution.
- Advisory enrichment runs inside the same async task as pattern matching — no IPC
- `VulnerabilityCandidate` flows directly into `DiscoveryQuery` for LLM reasoning

---

## 5. Confidence Model

| Source | Confidence | Rationale |
|--------|-----------|-----------|
| `LocalAdvisoryCache` | 0.85 | Curator-reviewed, structured ranges, exact version match |
| `OsvFeed` (strong mapping) | 0.75 | Live data, well-known ecosystem (e.g. nginx → Bitnami) |
| `OsvFeed` (best-effort mapping) | 0.50 | Ecosystem guess; may return unrelated packages |
| `BannerHeuristic` | 0.40 | No advisory lookup, version string heuristic only |

The LLM reasoning loop uses confidence to weight `VulnerabilityCandidate` entries in the `DiscoveryQuery`. PolicyGate requires confidence ≥ 0.7 for propagation approval.

---

## 6. Version Range Matching

Previous approach (Issue #128, superseded): `detected_version < fixed_version`

Problem: This produces false positives for vulnerabilities that affect only a narrow version window. For example, CVE-2021-41773 affects **only** Apache 2.4.49; a server at 2.4.30 would incorrectly match under the old logic.

Current approach (Issue #131): Structured `ranges` field with `[introduced, fixed)` half-open intervals.

```json
{
  "advisory_id": "CVE-2021-41773",
  "ranges": [
    { "introduced": "2.4.49", "fixed": "2.4.50" }
  ]
}
```

Matching logic:
1. If `ranges` is non-empty: `any(range.introduced <= detected < range.fixed)`
2. If `ranges` is empty (legacy): `detected < fixed_version` (conservative, no lower bound)

---

## 7. Recommendations

1. **Maintain advisory cache files** in `examples/advisory-cache/` with structured `ranges` for all new entries. Legacy `fixed_version`-only entries are still supported but produce conservative (no lower bound) matching.

2. **Prefer `OsvFeed` for services not in the local cache.** The auto mode already implements this fallback. For services where OSV ecosystem mapping is weak (e.g. OpenSSH, OpenSSL), treat `OsvFeed` candidates as hypothesis-generating rather than high-confidence.

3. **`OnlineRequired` mode** is appropriate for integration tests and Docker Lab validation. It guarantees fresh OSV data and prevents stale cache from masking online failures.

4. **physarum-sporangium PR #133** (merged 2026-06-02) completed the
project-scoped native feature port. This means parity for the protocols and
features intentionally supported by the organism, not behavioral equivalence
with every Nuclei runtime feature. The full imported template snapshot is stored
under `crates/physarum-sporangium/templates/nuclei-legacy/` and compressed into
`nuclei-templates.tar.zst`, which is embedded in the binary.

---

*End of document. For changes to this analysis, open a PR updating this file with the rationale.*

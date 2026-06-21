# physarum-sporangium — Template Catalog and LLM Integration Model

**Issue:** #136  
**Status:** Current implementation reference through v0.5.5
**Author:** Dev Lead (AI-assisted)  
**Date:** 2026-06-05  
**Related PRs:** #133 (Nuclei port), #132 (VulnIntel pipeline)

---

## 1. Overview

`physarum-sporangium` is the native Rust detection engine for the physarum-maze organism. It absorbs the role that the Nuclei scanner plays in traditional security tooling — running structured detection templates against discovered services — but is tightly integrated with the `physarum-llm` evidence loop rather than producing standalone reports.

This document covers:
- How templates are loaded and selected at runtime
- The anatomy of a `PatternTemplate` and how its metadata feeds the LLM
- The `physarum-maze` ↔ `physarum-sporangium` relationship
- The `nuclei-legacy/` template library inherited from upstream
- Future template development guidelines

---

## 2. Template Sources

`physarum-sporangium` has two template sources, merged at startup:

```text
catalog.rs              → builtin hand-crafted templates (compiled into the binary)
nuclei-templates.tar.zst → full Nuclei template library embedded in the binary
```

The embedded archive is extracted on demand into
`/tmp/physarum/templates/nuclei-legacy/` and reused when its sentinel is present,
unless `PHYSARUM_TEMPLATE_DIR` supplies an explicit external directory. Both
sources produce `PatternTemplate` values. The merge happens in
`catalog::all_templates_with_yaml()`:

```rust
pub fn all_templates_with_yaml() -> Vec<PatternTemplate> {
    let mut templates = all_templates();                         // builtins
    let builtin_ids: HashSet<String> = templates.iter().map(|t| t.id.clone()).collect();
    let dir = yaml_loader::template_dir();                       // PHYSARUM_TEMPLATE_DIR
    let filter = yaml_loader::TemplateFilter::from_env();        // env-var filter
    for t in yaml_loader::load_nuclei_templates(&dir, &filter) {
        if !builtin_ids.contains(&t.id) {
            templates.push(t);                                   // no duplicate IDs
        }
    }
    templates
}
```

Builtin templates take precedence over YAML templates on duplicate IDs.

---

## 3. Template Loading — YAML Loader

The YAML loader (`yaml_loader.rs`) converts Nuclei YAML format into `PatternTemplate` structs at startup.

### 3.1 Template Directory Resolution

Resolution order:

1. `PHYSARUM_TEMPLATE_DIR`, when explicitly configured for a lab, test or CI job.
2. The embedded `nuclei-templates.tar.zst` archive, extracted to
   `/tmp/physarum/templates/nuclei-legacy/`.

The binary is therefore self-contained for normal propagation. A Docker image
does not need to carry a separate template tree unless it intentionally overrides
the embedded catalog.

### 3.2 Filter Model (env vars)

| Variable | Format | Example | Effect |
|----------|--------|---------|--------|
| `PHYSARUM_TEMPLATE_TAGS` | comma-separated | `rce,cve,nginx` | Load only templates with at least one matching tag |
| `PHYSARUM_TEMPLATE_SEVERITY` | comma-separated | `critical,high` | Load only templates with matching severity |
| `PHYSARUM_TEMPLATE_IDS` | comma-separated | `CVE-2021-23017` | Load only templates with matching IDs (bypasses tag/severity) |

Empty value = no filter (all templates loaded). Filters are AND-combined (a template matching tag AND severity passes).

### 3.3 Supported Nuclei Protocols

| Nuclei block | Mapped to |
|-------------|-----------|
| `http:` | `PatternProtocol::Http` |
| `dns:` | `PatternProtocol::Dns` |
| `ssl:` | `PatternProtocol::Ssl` |
| `network:` / `tcp:` | `PatternProtocol::Tcp` |
| `javascript:`, `code:`, `headless:`, `dast:` | Skipped (out of scope) |

Templates with no supported protocol block are silently skipped during load.

---

## 4. PatternTemplate Anatomy

```rust
pub struct PatternTemplate {
    pub id: String,              // from template YAML id: field
    pub info: TemplateInfo,      // name, severity, tags, cve_id, cvss_score, references
    pub protocol: PatternProtocol,
    pub http_check: Option<HttpCheck>,
    pub tcp_request: Option<TcpRequest>,
    pub dns_request: Option<DnsRequest>,
    pub ssl_request: Option<SslRequest>,
    pub websocket_request: Option<WebSocketRequest>,
    pub matchers: Vec<PatternMatcher>,
    pub matchers_condition: MatchCondition,
    pub extractors: Vec<PatternExtractor>,
    pub stop_at_first_match: bool,
}

pub struct TemplateInfo {
    pub name: String,
    pub authors: Vec<String>,
    pub severity: SeverityHint,       // Critical, High, Medium, Low, Info
    pub tags: Vec<String>,
    pub cve_id: Option<String>,       // feeds VulnerabilityCandidate
    pub cvss_score: Option<f32>,      // feeds VulnerabilityCandidate
    pub references: Vec<String>,
    pub description: Option<String>,
    pub cwe_ids: Vec<String>,
}
```

`RunPolicy` is supplied by the caller when templates execute; it is not stored
inside each `PatternTemplate`. Its `allowed_check_ids` allowlist is evaluated
before network I/O.

### 4.1 How Template Findings Feed the LLM

When `physarum-spore` runs a template against a target and it fires:

```text
PatternFinding
  .template_id    → matched template ID
  .extracted_facts → HashMap<String, String>  (from Extractor results)
  .matched        → true
  .severity       → SeverityHint
```

The extracted facts (e.g. `server=nginx/1.18.0`, `framework=struts`) become the input to `VulnerabilityIntelService`. The service maps `(service_name, version)` to advisory cache entries, producing `VulnerabilityCandidate` structs that are attached to the `DiscoveryQuery` sent to the LLM.

```text
PatternFinding.extracted_facts["server"] = "nginx/1.18.0"
  → VulnerabilityIntelService(service="nginx", version="1.18.0")
  → LocalAdvisoryCache hit → CVE-2021-23017 (CVSS 7.7, confidence 0.85)
  → DiscoveryQuery.vulnerability_candidates = [VulnerabilityCandidate { cve_id: "CVE-2021-23017", ... }]
  → LLM receives enriched query with CVE context
  → LlmAttemptEvidence.cve_candidate_ids = ["CVE-2021-23017"]
```

Nothing in this chain is hardcoded. The CVE emerges from evidence.

---

## 5. physarum-maze ↔ physarum-sporangium Relationship

```text
physarum-maze (organism runtime)
  └── calls physarum-sporangium::catalog::all_templates_with_yaml()
      └── merges builtins + YAML-loaded templates
  └── calls physarum-sporangium::runner::evaluate_template(template, target)
      └── runs HTTP/DNS/SSL/TCP probe against target
      └── fires matchers → PatternFinding
      └── runs extractors → extracted_facts
  └── feeds PatternFinding into VulnerabilityIntelService
  └── feeds VulnerabilityCandidate into DiscoveryQuery
  └── sends DiscoveryQuery to physarum-llm
```

`physarum-maze` currently calls `all_templates_with_yaml()` in both template
selection/execution paths. PF-6 completed the wiring that was still pending when
the original version of this document was written.

---

## 6. nuclei-legacy Template Library

`crates/physarum-sporangium/templates/nuclei-legacy/` contains a full copy of the [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) library, imported as of 2026-06-02 (PR #133).

### 6.1 Directory Structure

```text
nuclei-legacy/
├── http/
│   ├── cves/           ~3,500 templates — CVE detections, tagged by year
│   ├── misconfiguration/  ~500 templates — exposed admin panels, debug endpoints
│   ├── exposures/      ~400 templates — sensitive file disclosures
│   ├── technologies/   ~600 templates — server/framework fingerprinting
│   ├── default-logins/ ~300 templates — default credential checks
│   └── ...
├── ssl/                ~38 templates  — TLS configuration, cert expiry
├── dns/                ~30 templates  — DNS zone transfer, subdomain takeover
├── network/            ~281 templates — raw TCP service detection
├── file/               ~447 templates — local file pattern matching
├── workflows/          ~206 templates — multi-step detection chains
├── cloud/              ~663 templates — AWS/GCP/Azure misconfiguration
├── code/               ~286 templates — source code pattern detection
└── dast/               ~249 templates — dynamic app security testing
```

**Total at the imported snapshot:** 13,264 templates, stored in the repository
and packaged into the binary as a compressed tar.zst archive.

### 6.2 Template Statistics (snapshot at import)

| Severity | Count |
|----------|-------|
| Critical | 1,788 |
| High | 2,893 |
| Medium | 2,789 |
| Low | 504 |
| Info | 4,997 |
| Unknown | 58 |

Top tags: `vuln` (6,621), `cve` (4,221), `discovery` (3,717), `rce` (952), `misconfig` (983)

See [TEMPLATES-STATS.md](../crates/physarum-sporangium/templates/nuclei-legacy/TEMPLATES-STATS.md) for the full breakdown.

### 6.3 What is Relevant for the Lab Model

The physarum-maze organism primarily targets:

| Category | Why relevant |
|----------|-------------|
| `http/cves/` | CVE detections with version extraction — direct VulnIntel input |
| `http/technologies/` | Server fingerprinting — feeds `extracted_facts["server"]` |
| `http/misconfiguration/` | Exposed panels and debug endpoints — attack surface expansion |
| `ssl/` | Certificate inspection, TLS version detection |
| `network/` | Raw TCP service fingerprinting |
| `dns/` | DNS zone transfer, subdomain enumeration |

Templates in `cloud/`, `code/`, `dast/`, `javascript/`, and `headless/` are either skipped by the YAML loader (unsupported protocol) or out of scope for the Docker Lab model.

### 6.4 Retained Documentation Files

The following upstream files are retained in `nuclei-legacy/` as reference material:

| File | Purpose |
|------|---------|
| `LICENSE.md` | Upstream license (MIT) — required for redistribution |
| `TEMPLATE-CREATION-GUIDE.md` | Reference for writing new physarum-compatible templates |
| `TEMPLATE-REVIEW-GUIDE.md` | Quality criteria — applicable when extending the catalog |
| `TEMPLATES-STATS.md` | Full tag/severity/directory breakdown |
| `TOP-10.md` | Top-10 statistics table |

Community files (`CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `PULL_REQUEST_TEMPLATE.md`, localized READMEs, `Templates-Bounty-FAQ.md`) have been removed as they reference the upstream project's contribution workflow, not physarum's.

---

## 7. Template Selection Strategy for Labs

### 7.1 Recommended Filters Per Lab Type

| Lab | `PHYSARUM_TEMPLATE_TAGS` | `PHYSARUM_TEMPLATE_SEVERITY` |
|-----|--------------------------|------------------------------|
| PF-5.2 (nginx CVE validation) | `nginx,cve` | `high,critical` |
| PF-6 Phase 1 (Struts RCE) | `rce,cve,struts` | `critical,high` |
| Full sweep | _(empty)_ | `critical,high,medium` |
| Fingerprinting only | `tech,discovery` | _(empty)_ |

### 7.2 Override by ID

When testing a specific CVE end-to-end:
```bash
PHYSARUM_TEMPLATE_IDS=CVE-2021-31805 docker compose -f docker/docker-compose-pf6.yml up
```
This bypasses tag/severity filters and loads only the named template.

---

## 8. Future Template Development

### 8.1 Writing physarum-Native Templates

New templates written specifically for physarum-maze should be placed in `catalog.rs` (as builtin Rust structs) rather than YAML when they:
- Require logic not expressible in Nuclei YAML (e.g. multi-step conditional flows)
- Need direct access to `PatternFinding.extracted_facts` with custom transformation
- Are organism-specific (e.g. physarum lineage probe, mTLS capability detection)

Templates that map cleanly to Nuclei YAML (HTTP matchers, banner extractors, SSL checks) can be added directly to `nuclei-legacy/` or a `nuclei-physarum/` subdirectory.

### 8.2 physarum-native Subdirectory (Future)

After PF-6, consider creating:

```text
crates/physarum-sporangium/templates/nuclei-physarum/
  ├── http/
  │   └── physarum-nginx-version-extract.yaml
  │   └── physarum-struts-rce-detect.yaml
  └── ssl/
      └── physarum-expired-cert.yaml
```

These would be physarum-authored templates, distinct from the upstream `nuclei-legacy/` library, and loaded alongside it via `PHYSARUM_TEMPLATE_DIR`.

### 8.3 Advisory Cache as the CVE Layer

The correct pattern for CVE coverage is:

```text
generic detection template (extracts version)
  +
advisory cache entry (maps version → CVE)
  =
CVE-enriched DiscoveryQuery for LLM
```

Do not create a separate template per CVE. One `server-version-exposed` template + one advisory cache entry covers the full version range of a CVE automatically.

---

*End of document. See [ROADMAP.md](./ROADMAP.md) and `docker/pf6-lab.sh` for the
implemented PF-6 validation path.*

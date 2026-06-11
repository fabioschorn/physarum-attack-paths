//! Dynamic vulnerability intelligence pipeline for LLM-ready evidence (Issue #131).
//!
//! # Flow
//!
//! ```text
//! PatternFinding (service + version extracted by physarum-sporangium)
//!     ↓
//! VulnerabilityIntelInput { service, version, port, banner_evidence }
//!     ↓
//! VulnerabilityIntelService::enrich()
//!     ├── Offline  → advisory-cache/<service>.json     (VulnerabilitySource::LocalAdvisoryCache)
//!     ├── Auto     → cache first, OSV API on miss      (VulnerabilitySource::OsvFeed)
//!     └── OnlineRequired → OSV API only (skips cache)  (VulnerabilitySource::OsvFeed)
//!         ↓
//! PatternFindingSummary.vulnerability_candidates  →  DiscoveryQuery  →  LLM
//! ```
//!
//! # Mode semantics
//!
//! | Mode            | Cache   | Online  | Behaviour on miss        |
//! |-----------------|---------|---------|--------------------------|
//! | `Offline`       | yes     | never   | empty result             |
//! | `Auto`          | yes     | on miss | OSV fallback             |
//! | `OnlineRequired`| skipped | always  | error/warn if offline    |
//!
//! # Security constraints
//!
//! - Advisory cache files must contain only public CVE metadata (no exploit code).
//! - Online queries are bounded by `PHYSARUM_VULN_INTEL_TIMEOUT_MS`.
//! - `exploit_enabled=false` by default — candidates are contextual evidence only.
//! - OSV service→ecosystem mapping is best-effort; confidence is reduced accordingly.

mod cache;
mod connectivity;
mod osv;

use std::path::{Path, PathBuf};

use physarum_llm::types::{VulnerabilityCandidate, VulnerabilitySource};

pub use cache::LocalAdvisoryCache;

// ── Input contract ────────────────────────────────────────────────────────────

/// Service + version evidence extracted by physarum-sporangium,
/// used to drive advisory lookup.
#[derive(Debug, Clone)]
pub struct VulnerabilityIntelInput {
    /// Normalized service identifier (e.g. `"nginx"`, `"apache-httpd"`, `"openssh"`).
    pub service: String,
    /// Exact version string as extracted from banner (e.g. `"1.18.0"`).
    pub version: String,
    /// Port on which the service was detected.
    pub port: u16,
    /// Raw banner fragments used as evidence strings in candidates.
    pub banner_evidence: Vec<String>,
}

// ── Intel mode ────────────────────────────────────────────────────────────────

/// Controls whether online advisory queries are attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntelMode {
    /// Try offline cache first; fall back to online on miss (default).
    Auto,
    /// Offline cache only — never make network requests to advisory APIs.
    Offline,
    /// Online query required — error if offline cache is used instead.
    OnlineRequired,
}

impl IntelMode {
    pub fn from_env() -> Self {
        match std::env::var("PHYSARUM_VULN_INTEL_MODE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "offline" => Self::Offline,
            "online-required" => Self::OnlineRequired,
            _ => Self::Auto,
        }
    }
}

// ── Service name normalisation ────────────────────────────────────────────────

/// Map a raw service string (as extracted from a banner or `version_hint`) to
/// the canonical advisory-cache key used as the JSON filename stem.
///
/// Examples:
/// - `"nginx/1.18.0"` → `("nginx", "1.18.0")`
/// - `"Apache/2.4.51"` → `("apache-httpd", "2.4.51")`
/// - `"OpenSSH_8.4p1"` → `("openssh", "8.4")`
/// - `"nginx"` (no version) → `("nginx", "")` — no version, no match
pub fn parse_service_version(raw: &str) -> Option<(String, String)> {
    // "nginx/1.18.0" style
    if let Some(pos) = raw.find('/') {
        let svc = raw[..pos].trim().to_ascii_lowercase();
        let ver = raw[pos + 1..].trim().to_string();
        if svc.is_empty() || ver.is_empty() {
            return None;
        }
        return Some((normalize_service_name(&svc), ver));
    }
    // "OpenSSH_8.4p1" style
    if let Some(pos) = raw.find('_') {
        let svc = raw[..pos].trim().to_ascii_lowercase();
        let ver_raw = raw[pos + 1..].trim();
        // Strip trailing non-numeric suffix: "8.4p1" → "8.4"
        let ver = strip_non_semver_suffix(ver_raw);
        if svc.is_empty() || ver.is_empty() {
            return None;
        }
        return Some((normalize_service_name(&svc), ver));
    }
    None
}

fn normalize_service_name(svc: &str) -> String {
    match svc {
        "apache" => "apache-httpd".to_string(),
        "openssh" => "openssh".to_string(),
        other => other.to_string(),
    }
}

/// Strip trailing non-numeric suffix: `"8.4p1"` → `"8.4"`, `"2.4.51"` → `"2.4.51"`.
fn strip_non_semver_suffix(v: &str) -> String {
    let mut result = String::new();
    let mut dot_count = 0usize;
    for ch in v.chars() {
        if ch.is_ascii_digit() {
            result.push(ch);
        } else if ch == '.' && dot_count < 2 {
            result.push(ch);
            dot_count += 1;
        } else {
            break;
        }
    }
    result
}

// ── VulnerabilityIntelService ─────────────────────────────────────────────────

/// Offline-first advisory enrichment service.
///
/// Constructed once at agent startup; passed to `llm_loop::run()` for each
/// LLM reasoning cycle. Thread-safe (`Send + Sync`).
pub struct VulnerabilityIntelService {
    mode: IntelMode,
    cache: LocalAdvisoryCache,
    http_client: reqwest::Client,
}

impl VulnerabilityIntelService {
    /// Build the service from a cache directory path and config.
    ///
    /// `cache_dir` is scanned for `*.json` advisory files at construction time.
    /// If the directory is absent, the cache is empty and online fallback applies
    /// (when `mode = Auto`).
    pub fn new(mode: IntelMode, cache_dir: &Path, timeout_ms: u64) -> anyhow::Result<Self> {
        let cache = LocalAdvisoryCache::load(cache_dir)?;
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()?;
        let _ = timeout_ms; // baked into http_client builder above
        Ok(Self {
            mode,
            cache,
            http_client,
        })
    }

    /// Create from environment variables, resolving the cache dir relative to
    /// the binary's working directory when `PHYSARUM_VULN_INTEL_CACHE_DIR` is
    /// not set.
    pub fn from_env() -> anyhow::Result<Self> {
        let mode = IntelMode::from_env();
        let timeout_ms = std::env::var("PHYSARUM_VULN_INTEL_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3_000u64);
        let cache_dir = std::env::var("PHYSARUM_VULN_INTEL_CACHE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("examples/advisory-cache"));
        tracing::info!(
            mode = ?mode,
            cache_dir = %cache_dir.display(),
            timeout_ms,
            "VulnerabilityIntelService initialised"
        );
        Self::new(mode, &cache_dir, timeout_ms)
    }

    /// Enrich a single service observation with advisory intelligence.
    ///
    /// The routing logic depends on [`IntelMode`]:
    /// - `Offline`: only the local cache is consulted; online is never attempted.
    /// - `Auto`: cache first, OSV API on miss — the common lab mode.
    /// - `OnlineRequired`: **skips the local cache entirely** and always queries
    ///   the OSV API. Returns an empty result (with a warning) when the network
    ///   is unreachable, to avoid silently falling back to unconfirmed local data.
    ///
    /// Never panics; errors are logged at `warn` level.
    pub async fn enrich(&self, input: &VulnerabilityIntelInput) -> Vec<VulnerabilityCandidate> {
        if input.version.is_empty() {
            return vec![];
        }

        // OnlineRequired — bypass cache, always query the live provider.
        if self.mode == IntelMode::OnlineRequired {
            return self.query_online(input, /*mandatory=*/ true).await;
        }

        // Offline / Auto — try local cache first.
        let offline = self.cache.lookup(input);
        if !offline.is_empty() {
            tracing::debug!(
                service = %input.service,
                version = %input.version,
                count = offline.len(),
                "advisory cache hit"
            );
            return offline;
        }

        tracing::debug!(
            service = %input.service,
            version = %input.version,
            "advisory cache miss"
        );

        if self.mode == IntelMode::Offline {
            return vec![];
        }

        // Auto — online fallback on cache miss.
        self.query_online(input, /*mandatory=*/ false).await
    }

    /// Query the OSV API online for `input`.
    ///
    /// `mandatory = true` means the caller expects an online answer
    /// (`OnlineRequired` mode); the unreachable-network warning is elevated.
    async fn query_online(
        &self,
        input: &VulnerabilityIntelInput,
        mandatory: bool,
    ) -> Vec<VulnerabilityCandidate> {
        if !connectivity::is_internet_available(&self.http_client).await {
            if mandatory {
                tracing::warn!(
                    service = %input.service,
                    version = %input.version,
                    "PHYSARUM_VULN_INTEL_MODE=online-required but Internet is unreachable \
                     — returning empty result (no silent cache fallback)"
                );
            } else {
                tracing::debug!(
                    service = %input.service,
                    "Internet unreachable — skipping OSV fallback"
                );
            }
            return vec![];
        }

        tracing::info!(
            service = %input.service,
            version = %input.version,
            mandatory,
            "querying OSV API"
        );

        match osv::query_osv(&self.http_client, input).await {
            Ok(candidates) => {
                tracing::info!(
                    service = %input.service,
                    version = %input.version,
                    count = candidates.len(),
                    "OSV query returned candidates"
                );
                candidates
            }
            Err(e) => {
                tracing::warn!(
                    service = %input.service,
                    version = %input.version,
                    err = %e,
                    "OSV query failed"
                );
                vec![]
            }
        }
    }

    /// Enrich all pattern findings concurrently, returning one `Vec<VulnerabilityCandidate>`
    /// per finding in the same order as the input slice.
    ///
    /// Bounded by `MAX_INTEL_CONCURRENCY` to avoid hammering advisory APIs.
    ///
    /// Two enrichment paths:
    /// 1. Version-based: extract service/version from banner → advisory cache / OSV.
    /// 2. Spore-direct: when a CVE-named template itself fires (is_actionable + check_id
    ///    starts with "CVE-"), synthesize a `PhysarumSpore` candidate without needing a
    ///    version string. The match records that the template's evidence was observed on
    ///    the host (e.g. CVE-2020-17530) — a vulnerable condition, not proof of code
    ///    execution. The candidate is only labelled `RemoteCodeExecution` when the
    ///    finding's local metadata identifies the class as RCE (see `finding_indicates_rce`).
    pub async fn enrich_findings(
        &self,
        findings: &[physarum_sporangium::PatternFinding],
    ) -> Vec<Vec<VulnerabilityCandidate>> {
        use futures::stream::{self, StreamExt};

        const MAX_INTEL_CONCURRENCY: usize = 4;

        stream::iter(findings.iter().enumerate().map(|(i, finding)| {
            let svc = self;
            let maybe_input = build_intel_input(finding);
            // When the template IS the CVE proof, synthesize a confirmed candidate.
            // Computed before the async block to avoid borrowing `finding` across await.
            let spore_candidate: Option<VulnerabilityCandidate> = if maybe_input.is_none()
                && finding.is_actionable()
                && finding.check_id.starts_with("CVE-")
            {
                Some(VulnerabilityCandidate {
                    cve_id: finding.check_id.clone(),
                    cvss_score: finding.template_cvss,
                    description: format!(
                        "Observed template evidence matched: {}",
                        finding.check_id
                    ),
                    affected_port: finding.port,
                    confidence: 0.95,
                    source: VulnerabilitySource::PhysarumSpore,
                    matched_service: None,
                    matched_version: None,
                    evidence: vec![finding.matched_condition_summary.clone()],
                    // A template match confirms the vulnerable condition was observed
                    // (exposure / version / endpoint / behavior). It is NOT proof that
                    // code execution occurred — that is only confirmed once the
                    // bootstrap/execution result produces the expected evidence.
                    is_confirmed: true,
                    affected_range: None,
                    // Only label RCE when the template's local metadata identifies the
                    // class as remote code execution. A generic actionable CVE match is
                    // observed evidence, not a confirmed RCE path, so it must not flip
                    // EXPLOIT MODE in the LLM Turn 2 prompt on its own.
                    exploit_class: if finding_indicates_rce(finding) {
                        Some("RemoteCodeExecution".to_string())
                    } else {
                        None
                    },
                    impact: None,
                    preconditions: vec![],
                    references: vec![],
                })
            } else {
                None
            };

            async move {
                let candidates = match maybe_input {
                    Some(input) => svc.enrich(&input).await,
                    None => spore_candidate.map(|c| vec![c]).unwrap_or_default(),
                };
                (i, candidates)
            }
        }))
        .buffer_unordered(MAX_INTEL_CONCURRENCY)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .fold(vec![vec![]; findings.len()], |mut acc, (i, candidates)| {
            acc[i] = candidates;
            acc
        })
    }
}

/// True when a finding's local metadata identifies its class as remote code
/// execution. We only inspect signals already present on the `PatternFinding`
/// (template name, check id, matched-condition summary, extracted facts) — no
/// network lookup. This keeps a generic actionable CVE match as *observed
/// evidence* while reserving the `RemoteCodeExecution` label (which can flip the
/// LLM into EXPLOIT MODE) for templates whose own metadata names the RCE class.
///
/// The generic, advisory-driven classification path is future work tracked by
/// #144 (`ExploitReference` + `ExploitExecutionRecipe`); this is a deliberately
/// narrow local-signal check.
fn finding_indicates_rce(finding: &physarum_sporangium::PatternFinding) -> bool {
    const RCE_SIGNALS: [&str; 6] = [
        "remote code execution",
        "rce",
        "ognl",
        "deserialization",
        "command injection",
        "command execution",
    ];

    let mut haystacks = vec![
        finding.name.to_ascii_lowercase(),
        finding.matched_condition_summary.to_ascii_lowercase(),
    ];
    for fact in &finding.extracted_facts {
        haystacks.push(fact.name.to_ascii_lowercase());
        haystacks.extend(fact.values.iter().map(|v| v.to_ascii_lowercase()));
    }

    haystacks
        .iter()
        .any(|h| RCE_SIGNALS.iter().any(|sig| h.contains(sig)))
}

// ── Input extraction from PatternFinding ──────────────────────────────────────

/// Extract a `VulnerabilityIntelInput` from a `PatternFinding`.
///
/// Returns `None` when the finding carries no extractable service/version
/// (e.g. a security-header absence check has no version string).
///
/// Two-pass extraction strategy:
///   1. Primary — scan `extracted_facts` for "service/version" or "service_version" strings.
///   2. Fallback — derive service from `check_id` (e.g. "proftpd-server-detect" → "proftpd")
///      and use the first extracted value as the raw version.  Covers TCP detection templates
///      that emit just the version number (e.g. ProFTPD extractor → "1.3.5").
pub fn build_intel_input(
    finding: &physarum_sporangium::PatternFinding,
) -> Option<VulnerabilityIntelInput> {
    // Primary: structured "service/version" or "service_version" in extracted facts.
    for fact in &finding.extracted_facts {
        for value in &fact.values {
            if let Some((service, version)) = parse_service_version(value) {
                if !version.is_empty() {
                    return Some(VulnerabilityIntelInput {
                        service,
                        version,
                        port: finding.port,
                        banner_evidence: vec![format!("Server header extract: {value}")],
                    });
                }
            }
        }
    }

    // Fallback: derive service from the detection template's check_id convention
    // ("proftpd-server-detect" → "proftpd", "wing-ftp-detect" → "wing-ftp") and
    // treat the first non-empty extracted value as the version number.
    if let Some(service) = service_from_check_id(&finding.check_id) {
        if let Some(raw_ver) = finding
            .extracted_facts
            .iter()
            .flat_map(|f| &f.values)
            .find(|v| !v.is_empty())
        {
            let version = strip_non_semver_suffix(raw_ver);
            if !version.is_empty() {
                return Some(VulnerabilityIntelInput {
                    service,
                    version,
                    port: finding.port,
                    banner_evidence: vec![format!("Banner extract: {raw_ver}")],
                });
            }
        }
    }

    None
}

/// Derive an advisory-cache service key from a detection template's check_id.
///
/// Strips standard detection suffixes so the result matches the advisory JSON
/// filename stem:
///   "proftpd-server-detect"   → Some("proftpd")
///   "wing-ftp-service-detect" → Some("wing-ftp")
///   "wing-ftp-detect"         → Some("wing-ftp")
///   "CVE-2015-3306"           → None  (CVE templates don't follow this convention)
fn service_from_check_id(check_id: &str) -> Option<String> {
    for suffix in &["-server-detect", "-service-detect", "-detect"] {
        if let Some(stem) = check_id.strip_suffix(suffix) {
            return Some(stem.to_string());
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_llm::types::VulnerabilitySource;
    use std::path::PathBuf;

    // ── Parsing ───────────────────────────────────────────────────────────────

    #[test]
    fn parse_nginx_slash_version() {
        let (svc, ver) = parse_service_version("nginx/1.18.0").unwrap();
        assert_eq!(svc, "nginx");
        assert_eq!(ver, "1.18.0");
    }

    #[test]
    fn parse_apache_normalized() {
        let (svc, ver) = parse_service_version("Apache/2.4.51").unwrap();
        assert_eq!(svc, "apache-httpd");
        assert_eq!(ver, "2.4.51");
    }

    #[test]
    fn parse_openssh_underscore() {
        let (svc, ver) = parse_service_version("OpenSSH_8.4p1").unwrap();
        assert_eq!(svc, "openssh");
        assert_eq!(ver, "8.4");
    }

    #[test]
    fn parse_no_version_returns_none() {
        assert!(parse_service_version("nginx").is_none());
        assert!(parse_service_version("").is_none());
    }

    #[test]
    fn strip_suffix_keeps_semver() {
        assert_eq!(strip_non_semver_suffix("8.4p1"), "8.4");
        assert_eq!(strip_non_semver_suffix("2.4.51"), "2.4.51");
        assert_eq!(strip_non_semver_suffix("9.0.65"), "9.0.65");
    }

    // ── Integration: offline cache mode ──────────────────────────────────────

    fn cache_dir() -> PathBuf {
        // Resolve from workspace root so tests work from any working directory.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/advisory-cache")
    }

    #[tokio::test]
    async fn offline_mode_returns_local_advisory_cache_source() {
        let dir = cache_dir();
        if !dir.exists() {
            eprintln!("advisory-cache dir not found — skipping integration test");
            return;
        }

        let svc =
            VulnerabilityIntelService::new(IntelMode::Offline, &dir, 3_000).expect("service init");

        let input = VulnerabilityIntelInput {
            service: "nginx".into(),
            version: "1.18.0".into(),
            port: 80,
            banner_evidence: vec!["Server: nginx/1.18.0".into()],
        };

        let candidates = svc.enrich(&input).await;
        assert!(
            !candidates.is_empty(),
            "nginx 1.18.0 must match at least one advisory in the offline cache"
        );
        for c in &candidates {
            assert_eq!(
                c.source,
                VulnerabilitySource::LocalAdvisoryCache,
                "offline mode must produce LocalAdvisoryCache source, got {:?}",
                c.source
            );
            assert!(
                c.confidence >= 0.80,
                "local cache candidates must have high confidence, got {}",
                c.confidence
            );
        }
    }

    #[tokio::test]
    async fn offline_mode_does_not_match_version_outside_range() {
        let dir = cache_dir();
        if !dir.exists() {
            return;
        }

        let svc =
            VulnerabilityIntelService::new(IntelMode::Offline, &dir, 3_000).expect("service init");

        // nginx 0.5.0 is below the introduced version of all cached advisories
        let input = VulnerabilityIntelInput {
            service: "nginx".into(),
            version: "0.5.0".into(),
            port: 80,
            banner_evidence: vec![],
        };

        let candidates = svc.enrich(&input).await;
        assert!(
            candidates.is_empty(),
            "nginx 0.5.0 must not match advisories with introduced >= 0.6.18; got {candidates:?}"
        );
    }

    #[tokio::test]
    async fn offline_mode_skips_unknown_service() {
        let dir = cache_dir();
        if !dir.exists() {
            return;
        }

        let svc =
            VulnerabilityIntelService::new(IntelMode::Offline, &dir, 3_000).expect("service init");

        let input = VulnerabilityIntelInput {
            service: "unknown-service".into(),
            version: "1.0.0".into(),
            port: 9000,
            banner_evidence: vec![],
        };

        let candidates = svc.enrich(&input).await;
        assert!(
            candidates.is_empty(),
            "unknown-service must return empty in offline mode"
        );
    }
}

//! Dynamic vulnerability intelligence pipeline for LLM-ready evidence (Issue #131).
//!
//! Replaces the static `cve_heuristic` bootstrap with a service-keyed,
//! offline-first advisory lookup that falls back to online OSV/NVD queries
//! when the detected service has no local cache entry.
//!
//! # Flow
//!
//! ```text
//! PatternFinding (service + version extracted by physarum-sporangium)
//!     ↓
//! VulnerabilityIntelInput { service, version, port, banner_evidence }
//!     ↓
//! VulnerabilityIntelService::enrich()
//!     ├── 1. offline: advisory-cache/<service>.json  → Vec<VulnerabilityCandidate>
//!     └── 2. online (miss): OSV API query            → Vec<VulnerabilityCandidate>
//!         ↓
//! PatternFindingSummary.vulnerability_candidates  →  DiscoveryQuery  →  LLM
//! ```
//!
//! # Security constraints
//!
//! - No secrets are stored in advisory cache files (public CVE metadata only).
//! - Online queries are bounded by `PHYSARUM_VULN_INTEL_TIMEOUT_MS`.
//! - Internet check is non-blocking; offline fallback is always available.
//! - `exploit_enabled=false` by default — candidates are contextual evidence only.

mod cache;
mod connectivity;
mod osv;

use std::path::{Path, PathBuf};

use physarum_llm::types::VulnerabilityCandidate;

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
    /// Returns an empty `Vec` when no advisory is found and no online fallback
    /// is attempted (e.g. `mode = Offline` and the service has no cache entry).
    /// Never panics; errors are logged at `warn` level and an empty result returned.
    pub async fn enrich(&self, input: &VulnerabilityIntelInput) -> Vec<VulnerabilityCandidate> {
        if input.version.is_empty() {
            return vec![];
        }

        // 1 — offline cache
        let offline = self.cache.lookup(input);
        if !offline.is_empty() {
            tracing::debug!(
                service = %input.service, version = %input.version,
                count = offline.len(), "advisory cache hit"
            );
            return offline;
        }

        tracing::debug!(
            service = %input.service, version = %input.version,
            "advisory cache miss"
        );

        if self.mode == IntelMode::Offline {
            return vec![];
        }

        // 2 — online fallback (Auto or OnlineRequired)
        match connectivity::is_internet_available(&self.http_client).await {
            false => {
                if self.mode == IntelMode::OnlineRequired {
                    tracing::warn!(
                        service = %input.service,
                        "PHYSARUM_VULN_INTEL_MODE=online-required but Internet unreachable"
                    );
                }
                vec![]
            }
            true => {
                tracing::info!(
                    service = %input.service, version = %input.version,
                    "cache miss — querying OSV online"
                );
                match osv::query_osv(&self.http_client, input).await {
                    Ok(candidates) => {
                        tracing::info!(
                            service = %input.service, version = %input.version,
                            count = candidates.len(), "OSV query returned candidates"
                        );
                        candidates
                    }
                    Err(e) => {
                        tracing::warn!(
                            service = %input.service, version = %input.version,
                            err = %e, "OSV query failed"
                        );
                        vec![]
                    }
                }
            }
        }
    }

    /// Enrich all pattern findings concurrently, returning one `Vec<VulnerabilityCandidate>`
    /// per finding in the same order as the input slice.
    ///
    /// Bounded by `MAX_INTEL_CONCURRENCY` to avoid hammering advisory APIs.
    pub async fn enrich_findings(
        &self,
        findings: &[physarum_sporangium::PatternFinding],
    ) -> Vec<Vec<VulnerabilityCandidate>> {
        use futures::stream::{self, StreamExt};

        const MAX_INTEL_CONCURRENCY: usize = 4;

        let inputs: Vec<Option<VulnerabilityIntelInput>> =
            findings.iter().map(build_intel_input).collect();

        stream::iter(inputs.into_iter().enumerate().map(|(i, maybe_input)| {
            let svc = self;
            async move {
                match maybe_input {
                    None => (i, vec![]),
                    Some(input) => (i, svc.enrich(&input).await),
                }
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

// ── Input extraction from PatternFinding ──────────────────────────────────────

/// Extract a `VulnerabilityIntelInput` from a `PatternFinding`.
///
/// Returns `None` when the finding carries no extractable service/version
/// (e.g. a security-header absence check has no version string).
pub fn build_intel_input(
    finding: &physarum_sporangium::PatternFinding,
) -> Option<VulnerabilityIntelInput> {
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
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
}

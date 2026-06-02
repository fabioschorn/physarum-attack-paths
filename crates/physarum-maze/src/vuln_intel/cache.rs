//! Local offline advisory cache — reads `advisory-cache/<service>.json` at startup.
//!
//! # Advisory JSON schema (extended)
//!
//! ```json
//! [
//!   {
//!     "advisory_id": "CVE-2021-23017",
//!     "ranges": [
//!       { "introduced": "0.6.18", "fixed": "1.21.0" }
//!     ],
//!     "fixed_version": "1.21.0",
//!     "affected_range": ">= 0.6.18, < 1.21.0",
//!     "cvss_score": 7.7,
//!     "severity": "High",
//!     "description": "...",
//!     "impact": "...",
//!     "exploit_class": "Memory Corruption",
//!     "preconditions": [...],
//!     "references": [...]
//!   }
//! ]
//! ```
//!
//! The `ranges` field enables accurate half-open interval matching
//! (`introduced <= detected_version < fixed`) to eliminate false positives that
//! arise from a simple `detected < fixed` comparison on very old versions.
//! When `ranges` is absent the code falls back to the legacy `fixed_version`
//! field as an exclusive upper bound with no lower bound (matches all prior).

use std::collections::HashMap;
use std::path::Path;

use physarum_llm::types::{VulnerabilityCandidate, VulnerabilitySource};
use serde::Deserialize;

use super::VulnerabilityIntelInput;

// ── Affected version range ────────────────────────────────────────────────────

/// A single half-open semver interval: `[introduced, fixed)`.
///
/// - `introduced`: first affected version (inclusive). `None` = affected from 0.0.0.
/// - `fixed`: first version that is no longer affected (exclusive). `None` = no known fix.
#[derive(Debug, Clone, Deserialize)]
pub struct AffectedRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

impl AffectedRange {
    /// Returns `true` when `detected` falls within this range.
    ///
    /// `introduced` is inclusive; `fixed` is exclusive.
    /// A missing `introduced` matches all versions up to `fixed`.
    /// A missing `fixed` matches all versions from `introduced`.
    pub fn contains(&self, detected: (u64, u64, u64)) -> bool {
        let after_intro = match &self.introduced {
            Some(intro) => parse_semver(intro)
                .map(|intro_v| detected >= intro_v)
                .unwrap_or(false),
            None => true,
        };
        let before_fixed = match &self.fixed {
            Some(fixed) => parse_semver(fixed)
                .map(|fixed_v| detected < fixed_v)
                .unwrap_or(false),
            None => true,
        };
        after_intro && before_fixed
    }
}

// ── Advisory entry (JSON schema) ─────────────────────────────────────────────

/// Single advisory record stored in `advisory-cache/<service>.json`.
///
/// Committed files must contain only public CVE/advisory metadata —
/// no exploit code, no payload strings, no internal IP addresses.
#[derive(Debug, Clone, Deserialize)]
pub struct AdvisoryEntry {
    /// CVE or GHSA identifier (e.g. `"CVE-2021-23017"`).
    pub advisory_id: String,
    /// Structured affected version ranges (preferred over `fixed_version`).
    /// At least one range must match `detected_version` for the advisory to fire.
    #[serde(default)]
    pub ranges: Vec<AffectedRange>,
    /// Legacy: first version in which the vulnerability is fixed (exclusive upper bound).
    /// Used when `ranges` is empty; treated as `[0.0.0, fixed_version)`.
    #[serde(default)]
    pub fixed_version: String,
    /// Human-readable affected range (e.g. `">= 0.6.18, < 1.21.0"`). Display only.
    pub affected_range: String,
    pub cvss_score: f32,
    /// Severity level string: `"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Info"`.
    /// Used by the advisory document display layer and for logging; not read by Rust match logic.
    #[allow(dead_code)]
    pub severity: String,
    pub description: String,
    pub impact: String,
    pub exploit_class: String,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

impl AdvisoryEntry {
    /// Returns `true` when `detected` is within the affected version window.
    ///
    /// Prefers `ranges` if populated; falls back to legacy `fixed_version` with
    /// no lower bound (conservative — any version below `fixed_version` matches).
    pub fn affects(&self, detected: (u64, u64, u64)) -> bool {
        if !self.ranges.is_empty() {
            return self.ranges.iter().any(|r| r.contains(detected));
        }
        // Legacy fallback: detected < fixed_version (no lower bound check)
        parse_semver(&self.fixed_version)
            .map(|fixed| detected < fixed)
            .unwrap_or(false)
    }
}

// ── Local advisory cache ──────────────────────────────────────────────────────

/// In-memory cache loaded from `advisory-cache/*.json` at startup.
///
/// Key: normalized service name (e.g. `"nginx"`, `"apache-httpd"`, `"openssh"`).
/// Value: list of `AdvisoryEntry` records for that service.
pub struct LocalAdvisoryCache {
    entries: HashMap<String, Vec<AdvisoryEntry>>,
}

impl LocalAdvisoryCache {
    /// Load all `*.json` files from `dir`.
    ///
    /// Each filename stem becomes the service key (e.g. `nginx.json` → `"nginx"`).
    /// Files that cannot be parsed are logged and skipped — startup continues.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let mut entries: HashMap<String, Vec<AdvisoryEntry>> = HashMap::new();

        if !dir.exists() {
            tracing::warn!(
                path = %dir.display(),
                "advisory cache directory not found — offline cache empty"
            );
            return Ok(Self { entries });
        }

        let read_dir = std::fs::read_dir(dir)?;
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let service_key = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_ascii_lowercase(),
                None => continue,
            };
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path.display(), err = %e, "failed to read advisory file");
                    continue;
                }
            };
            match serde_json::from_str::<Vec<AdvisoryEntry>>(&content) {
                Ok(advisories) => {
                    tracing::debug!(service = %service_key, count = advisories.len(), "loaded advisory cache");
                    entries.insert(service_key, advisories);
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(), err = %e,
                        "advisory file parse error — skipping"
                    );
                }
            }
        }

        tracing::info!(
            services = entries.len(),
            total_advisories = entries.values().map(|v| v.len()).sum::<usize>(),
            "offline advisory cache loaded"
        );
        Ok(Self { entries })
    }

    /// Look up advisory candidates for `input.service` + `input.version`.
    ///
    /// Uses structured `ranges` when present; falls back to `fixed_version`-only
    /// comparison for legacy entries.  Only returns advisories whose version
    /// window includes `input.version`.
    pub fn lookup(&self, input: &VulnerabilityIntelInput) -> Vec<VulnerabilityCandidate> {
        let Some(advisories) = self.entries.get(&input.service) else {
            return vec![];
        };

        let Some(detected) = parse_semver(&input.version) else {
            tracing::debug!(version = %input.version, "could not parse semver — skipping cache lookup");
            return vec![];
        };

        advisories
            .iter()
            .filter(|a| {
                let affected = a.affects(detected);
                tracing::debug!(
                    advisory = %a.advisory_id,
                    service = %input.service,
                    detected = %input.version,
                    ranges_count = a.ranges.len(),
                    affected,
                    "advisory range check"
                );
                affected
            })
            .map(|a| to_candidate(a, input))
            .collect()
    }
}

// ── Semver comparison ─────────────────────────────────────────────────────────

/// Parse `"1.18.0"` → `(1, 18, 0)`. Two-part versions map patch to 0.
pub fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<u64> = v
        .splitn(4, '.')
        .take(3)
        .filter_map(|p| p.parse().ok())
        .collect();
    match parts.as_slice() {
        [major, minor, patch] => Some((*major, *minor, *patch)),
        [major, minor] => Some((*major, *minor, 0)),
        _ => None,
    }
}

// ── Candidate construction ────────────────────────────────────────────────────

/// Build a `VulnerabilityCandidate` from an `AdvisoryEntry` + observed input.
///
/// Source is always `LocalAdvisoryCache` — this function is only called when
/// the offline cache produced the match.
pub fn to_candidate(
    entry: &AdvisoryEntry,
    input: &VulnerabilityIntelInput,
) -> VulnerabilityCandidate {
    VulnerabilityCandidate {
        cve_id: entry.advisory_id.clone(),
        cvss_score: Some(entry.cvss_score),
        description: entry.description.clone(),
        affected_port: input.port,
        confidence: 0.85,
        source: VulnerabilitySource::LocalAdvisoryCache,
        matched_service: Some(input.service.clone()),
        matched_version: Some(input.version.clone()),
        evidence: input.banner_evidence.clone(),
        is_confirmed: false,
        affected_range: Some(entry.affected_range.clone()),
        exploit_class: Some(entry.exploit_class.clone()),
        impact: Some(entry.impact.clone()),
        preconditions: entry.preconditions.clone(),
        references: entry.references.clone(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_ranges(intro: Option<&str>, fixed: Option<&str>) -> AdvisoryEntry {
        AdvisoryEntry {
            advisory_id: "CVE-TEST-0001".into(),
            ranges: vec![AffectedRange {
                introduced: intro.map(str::to_string),
                fixed: fixed.map(str::to_string),
            }],
            fixed_version: String::new(),
            affected_range: format!(
                "{}, {}",
                intro.map(|v| format!(">= {v}")).unwrap_or_default(),
                fixed.map(|v| format!("< {v}")).unwrap_or_default()
            ),
            cvss_score: 7.0,
            severity: "High".into(),
            description: "test".into(),
            impact: "test impact".into(),
            exploit_class: "DoS".into(),
            preconditions: vec![],
            references: vec![],
        }
    }

    fn entry_legacy(fixed: &str) -> AdvisoryEntry {
        AdvisoryEntry {
            advisory_id: "CVE-TEST-0002".into(),
            ranges: vec![],
            fixed_version: fixed.into(),
            affected_range: format!("< {fixed}"),
            cvss_score: 7.0,
            severity: "High".into(),
            description: "legacy test".into(),
            impact: "test impact".into(),
            exploit_class: "RCE".into(),
            preconditions: vec![],
            references: vec![],
        }
    }

    // ── Structured range matching ─────────────────────────────────────────────

    #[test]
    fn range_with_intro_and_fixed_matches_version_in_window() {
        let e = entry_ranges(Some("1.5.0"), Some("1.21.0"));
        // 1.18.0 is in [1.5.0, 1.21.0)
        assert!(e.affects(parse_semver("1.18.0").unwrap()));
    }

    #[test]
    fn range_does_not_match_version_below_introduced() {
        let e = entry_ranges(Some("1.5.0"), Some("1.21.0"));
        // 1.3.0 is below the introduced bound
        assert!(!e.affects(parse_semver("1.3.0").unwrap()));
    }

    #[test]
    fn range_does_not_match_version_at_fixed() {
        let e = entry_ranges(Some("1.5.0"), Some("1.21.0"));
        // 1.21.0 is the fixed version — not affected
        assert!(!e.affects(parse_semver("1.21.0").unwrap()));
    }

    #[test]
    fn range_does_not_match_version_above_fixed() {
        let e = entry_ranges(Some("1.5.0"), Some("1.21.0"));
        assert!(!e.affects(parse_semver("1.22.0").unwrap()));
    }

    #[test]
    fn range_with_no_intro_matches_from_zero() {
        let e = entry_ranges(None, Some("1.21.0"));
        // 0.9.0 has no lower bound
        assert!(e.affects(parse_semver("0.9.0").unwrap()));
    }

    #[test]
    fn range_with_no_fixed_matches_above_intro() {
        let e = entry_ranges(Some("1.5.0"), None);
        // Any version >= 1.5.0 matches (no fix released)
        assert!(e.affects(parse_semver("99.0.0").unwrap()));
    }

    // ── Legacy fixed_version fallback ─────────────────────────────────────────

    #[test]
    fn legacy_below_fixed_is_vulnerable() {
        let e = entry_legacy("1.21.0");
        assert!(e.affects(parse_semver("1.18.0").unwrap()));
    }

    #[test]
    fn legacy_at_fixed_is_not_vulnerable() {
        let e = entry_legacy("1.21.0");
        assert!(!e.affects(parse_semver("1.21.0").unwrap()));
    }

    #[test]
    fn legacy_above_fixed_is_not_vulnerable() {
        let e = entry_legacy("1.17.3");
        assert!(!e.affects(parse_semver("1.18.0").unwrap()));
    }

    // ── Semver parsing ────────────────────────────────────────────────────────

    #[test]
    fn parse_semver_two_part() {
        assert_eq!(parse_semver("1.21"), Some((1, 21, 0)));
    }

    #[test]
    fn parse_semver_invalid_returns_none() {
        assert!(parse_semver("abc").is_none());
        assert!(parse_semver("").is_none());
    }

    // ── Source attribution ────────────────────────────────────────────────────

    #[test]
    fn candidate_source_is_local_advisory_cache() {
        let entry = entry_legacy("2.0.0");
        let input = VulnerabilityIntelInput {
            service: "nginx".into(),
            version: "1.18.0".into(),
            port: 80,
            banner_evidence: vec![],
        };
        let candidate = to_candidate(&entry, &input);
        assert_eq!(candidate.source, VulnerabilitySource::LocalAdvisoryCache);
        assert!(
            candidate.confidence >= 0.80,
            "cache hits should have high confidence"
        );
    }
}

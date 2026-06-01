//! Local offline advisory cache — reads `advisory-cache/<service>.json` at startup.

use std::collections::HashMap;
use std::path::Path;

use physarum_llm::types::{VulnerabilityCandidate, VulnerabilitySource};
use serde::Deserialize;

use super::VulnerabilityIntelInput;

// ── Advisory entry (JSON schema) ─────────────────────────────────────────────

/// Single advisory record stored in `advisory-cache/<service>.json`.
///
/// Committed files must contain only public CVE/advisory metadata —
/// no exploit code, no payload strings, no internal IP addresses.
#[derive(Debug, Clone, Deserialize)]
pub struct AdvisoryEntry {
    /// CVE or GHSA identifier (e.g. `"CVE-2021-23017"`).
    pub advisory_id: String,
    /// First version in which the vulnerability is fixed (exclusive upper bound).
    /// All versions strictly below this are considered affected.
    pub fixed_version: String,
    /// Human-readable affected range (e.g. `"< 1.21.0"`). Display only.
    pub affected_range: String,
    pub cvss_score: f32,
    /// Severity level string: `"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Info"`.
    pub severity: String,
    pub description: String,
    pub impact: String,
    pub exploit_class: String,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
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
    /// Returns only entries where `input.version < entry.fixed_version`.
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
                parse_semver(&a.fixed_version)
                    .map(|fixed| detected < fixed)
                    .unwrap_or(false)
            })
            .inspect(|a| {
                tracing::debug!(
                    advisory = %a.advisory_id,
                    severity = %a.severity,
                    "advisory cache match"
                );
            })
            .map(|a| to_candidate(a, input, false))
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
pub fn to_candidate(
    entry: &AdvisoryEntry,
    input: &VulnerabilityIntelInput,
    online: bool,
) -> VulnerabilityCandidate {
    let source = if online {
        VulnerabilitySource::PhysarumSpore
    } else {
        VulnerabilitySource::NvdFeed
    };
    VulnerabilityCandidate {
        cve_id: entry.advisory_id.clone(),
        cvss_score: Some(entry.cvss_score),
        description: entry.description.clone(),
        affected_port: input.port,
        confidence: 0.70,
        source,
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

    fn make_entry(fixed: &str) -> AdvisoryEntry {
        AdvisoryEntry {
            advisory_id: "CVE-TEST-0001".into(),
            fixed_version: fixed.into(),
            affected_range: format!("< {fixed}"),
            cvss_score: 7.0,
            severity: "High".into(),
            description: "test".into(),
            impact: "test impact".into(),
            exploit_class: "DoS".into(),
            preconditions: vec![],
            references: vec![],
        }
    }

    fn make_input(version: &str) -> VulnerabilityIntelInput {
        VulnerabilityIntelInput {
            service: "nginx".into(),
            version: version.into(),
            port: 80,
            banner_evidence: vec![],
        }
    }

    #[test]
    fn semver_below_fixed_is_vulnerable() {
        let entry = make_entry("1.21.0");
        let input = make_input("1.18.0");
        let detected = parse_semver(&input.version).unwrap();
        let fixed = parse_semver(&entry.fixed_version).unwrap();
        assert!(detected < fixed);
    }

    #[test]
    fn semver_at_fixed_is_not_vulnerable() {
        let entry = make_entry("1.21.0");
        let input = make_input("1.21.0");
        let detected = parse_semver(&input.version).unwrap();
        let fixed = parse_semver(&entry.fixed_version).unwrap();
        assert!(!(detected < fixed));
    }

    #[test]
    fn semver_above_fixed_is_not_vulnerable() {
        let entry = make_entry("1.17.3");
        let input = make_input("1.18.0");
        let detected = parse_semver(&input.version).unwrap();
        let fixed = parse_semver(&entry.fixed_version).unwrap();
        assert!(!(detected < fixed));
    }

    #[test]
    fn parse_semver_two_part() {
        assert_eq!(parse_semver("1.21"), Some((1, 21, 0)));
    }

    #[test]
    fn parse_semver_invalid_returns_none() {
        assert!(parse_semver("abc").is_none());
        assert!(parse_semver("").is_none());
    }
}

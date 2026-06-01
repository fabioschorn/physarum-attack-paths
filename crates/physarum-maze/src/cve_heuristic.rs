//! Banner-heuristic CVE enrichment for `physarum-spore` pattern findings.
//!
//! Matches service version strings extracted from HTTP `Server` headers against a
//! static table of known CVEs. Produces `VulnerabilityCandidate` entries that are
//! embedded in `PatternFindingSummary` and forwarded to the LLM via `DiscoveryQuery`.
//!
//! This is evidence-only enrichment — no network probing, no exploit execution.
//! Confidence is intentionally conservative (0.7) because version range matches
//! are heuristic, not confirmed vulnerability scans.

use physarum_llm::types::{VulnerabilityCandidate, VulnerabilitySource};
use physarum_sporangium::finding::PatternFinding;

// ── Static CVE table ──────────────────────────────────────────────────────────

struct CveEntry {
    cve_id: &'static str,
    cvss_score: f32,
    description: &'static str,
    /// Returns `true` when (major, minor, patch) falls in the affected range.
    applies: fn(u64, u64, u64) -> bool,
}

static NGINX_CVES: &[CveEntry] = &[
    CveEntry {
        cve_id: "CVE-2021-23017",
        cvss_score: 7.7,
        description: "Off-by-one in the nginx resolver allows a DNS-forged-UDP attacker to \
                       overwrite 1 byte of heap memory — worker crash or potential code execution \
                       (nginx < 1.21.0)",
        applies: |major, minor, _patch| major == 1 && minor < 21,
    },
    CveEntry {
        cve_id: "CVE-2019-9511",
        cvss_score: 7.5,
        description: "HTTP/2 Data Dribble: WINDOW_UPDATE frames with small increments allow \
                       remote CPU exhaustion (nginx < 1.17.3 with ngx_http_v2_module)",
        applies: |major, minor, patch| major == 1 && (minor < 17 || (minor == 17 && patch < 3)),
    },
    CveEntry {
        cve_id: "CVE-2019-9516",
        cvss_score: 6.5,
        description: "HTTP/2 zero-length headers cause unbounded memory growth — \
                       remote memory exhaustion (nginx < 1.17.3 with ngx_http_v2_module)",
        applies: |major, minor, patch| major == 1 && (minor < 17 || (minor == 17 && patch < 3)),
    },
];

// ── Version parsing ───────────────────────────────────────────────────────────

/// Parse `"1.18.0"` → `(1, 18, 0)`.  Two-part versions map patch to 0.
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
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

/// Split `"nginx/1.18.0"` into `("nginx", "1.18.0")`.
fn split_service_version(s: &str) -> Option<(&str, &str)> {
    let mut it = s.splitn(2, '/');
    let svc = it.next()?.trim();
    let ver = it.next()?.trim();
    if svc.is_empty() || ver.is_empty() {
        return None;
    }
    Some((svc, ver))
}

// ── Public enrichment API ─────────────────────────────────────────────────────

/// Enrich a `PatternFinding` with CVE candidates derived from version strings
/// extracted from HTTP `Server` headers.
///
/// Only the `server-version-exposed` template typically produces version-containing
/// extracted facts, but the function is applied to all findings for completeness.
/// Returns an empty `Vec` when no match is found.
pub fn enrich_finding(finding: &PatternFinding) -> Vec<VulnerabilityCandidate> {
    let mut candidates: Vec<VulnerabilityCandidate> = Vec::new();

    for fact in &finding.extracted_facts {
        for value in &fact.values {
            let Some((service, version)) = split_service_version(value) else {
                continue;
            };

            let table: &[CveEntry] = match service.to_ascii_lowercase().as_str() {
                "nginx" => NGINX_CVES,
                _ => continue,
            };

            let Some((major, minor, patch)) = parse_semver(version) else {
                continue;
            };

            for entry in table {
                if !(entry.applies)(major, minor, patch) {
                    continue;
                }
                // Avoid duplicates if the same version string appears in multiple facts.
                if candidates.iter().any(|c| c.cve_id == entry.cve_id) {
                    continue;
                }
                candidates.push(VulnerabilityCandidate {
                    cve_id: entry.cve_id.to_string(),
                    cvss_score: Some(entry.cvss_score),
                    description: entry.description.to_string(),
                    affected_port: finding.port,
                    confidence: 0.70,
                    source: VulnerabilitySource::BannerHeuristic,
                    matched_service: Some(service.to_string()),
                    matched_version: Some(version.to_string()),
                    evidence: vec![format!("Server header extract: {value}")],
                    is_confirmed: false,
                });
            }
        }
    }

    candidates
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding_with_version(version_value: &str, port: u16) -> PatternFinding {
        use chrono::Utc;
        use physarum_sporangium::extractor::ExtractedFact;
        use physarum_sporangium::finding::EvidenceSource;
        use physarum_sporangium::template::{PatternProtocol, SeverityHint};

        PatternFinding {
            template_id: "server-version-exposed".into(),
            check_id: "server-version-exposed".into(),
            name: "Server Version Exposed".into(),
            target_ip: "172.20.0.3".parse().unwrap(),
            port,
            protocol: PatternProtocol::Http,
            severity_hint: SeverityHint::Low,
            confidence: 1.0,
            matched_condition_summary: format!("version-regex: {version_value}"),
            extracted_facts: vec![ExtractedFact {
                name: "version-string".into(),
                values: vec![version_value.to_string()],
            }],
            evidence_source: EvidenceSource::HttpProbe,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn nginx_1_18_0_matches_cve_2021_23017() {
        let finding = make_finding_with_version("nginx/1.18.0", 80);
        let candidates = enrich_finding(&finding);
        assert!(
            candidates.iter().any(|c| c.cve_id == "CVE-2021-23017"),
            "expected CVE-2021-23017 for nginx/1.18.0"
        );
    }

    #[test]
    fn nginx_1_14_0_matches_cve_2019_9511() {
        let finding = make_finding_with_version("nginx/1.14.0", 80);
        let candidates = enrich_finding(&finding);
        // 1.14.0 < 1.17.3 — CVE-2019-9511 applies
        assert!(
            candidates.iter().any(|c| c.cve_id == "CVE-2019-9511"),
            "expected CVE-2019-9511 for nginx/1.14.0"
        );
    }

    #[test]
    fn nginx_1_18_0_no_cve_2019_9511() {
        let finding = make_finding_with_version("nginx/1.18.0", 80);
        let candidates = enrich_finding(&finding);
        // 1.18.0 >= 1.17.3 — CVE-2019-9511 does not apply
        assert!(
            !candidates.iter().any(|c| c.cve_id == "CVE-2019-9511"),
            "CVE-2019-9511 must not match nginx/1.18.0 (>= 1.17.3 patched)"
        );
    }

    #[test]
    fn nginx_1_24_0_no_cve_2019_9511() {
        let finding = make_finding_with_version("nginx/1.24.0", 80);
        let candidates = enrich_finding(&finding);
        assert!(
            !candidates.iter().any(|c| c.cve_id == "CVE-2019-9511"),
            "CVE-2019-9511 must not match nginx/1.24.0"
        );
    }

    #[test]
    fn nginx_1_21_0_no_cve_2021_23017() {
        let finding = make_finding_with_version("nginx/1.21.0", 80);
        let candidates = enrich_finding(&finding);
        // CVE-2021-23017 affects < 1.21.0; 1.21.0 is patched
        assert!(
            !candidates.iter().any(|c| c.cve_id == "CVE-2021-23017"),
            "CVE-2021-23017 must not match nginx/1.21.0 (patched)"
        );
    }

    #[test]
    fn unknown_service_returns_empty() {
        let finding = make_finding_with_version("caddy/2.6.0", 80);
        assert!(enrich_finding(&finding).is_empty());
    }

    #[test]
    fn no_version_string_returns_empty() {
        let finding = make_finding_with_version("nginx", 80);
        assert!(enrich_finding(&finding).is_empty());
    }

    #[test]
    fn affected_port_propagated_correctly() {
        let finding = make_finding_with_version("nginx/1.18.0", 8080);
        let candidates = enrich_finding(&finding);
        for c in &candidates {
            assert_eq!(c.affected_port, 8080);
        }
    }

    #[test]
    fn no_duplicate_cve_for_repeated_value() {
        use chrono::Utc;
        use physarum_sporangium::extractor::ExtractedFact;
        use physarum_sporangium::finding::EvidenceSource;
        use physarum_sporangium::template::{PatternProtocol, SeverityHint};

        let finding = PatternFinding {
            template_id: "server-version-exposed".into(),
            check_id: "server-version-exposed".into(),
            name: "Server Version Exposed".into(),
            target_ip: "172.20.0.3".parse().unwrap(),
            port: 80,
            protocol: PatternProtocol::Http,
            severity_hint: SeverityHint::Low,
            confidence: 1.0,
            matched_condition_summary: "version-regex".into(),
            extracted_facts: vec![ExtractedFact {
                name: "version-string".into(),
                values: vec!["nginx/1.18.0".to_string(), "nginx/1.18.0".to_string()],
            }],
            evidence_source: EvidenceSource::HttpProbe,
            timestamp: Utc::now(),
        };
        let candidates = enrich_finding(&finding);
        let count = candidates
            .iter()
            .filter(|c| c.cve_id == "CVE-2021-23017")
            .count();
        assert_eq!(count, 1, "duplicate CVE entries must be deduplicated");
    }
}

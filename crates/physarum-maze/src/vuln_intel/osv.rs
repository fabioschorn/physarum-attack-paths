//! Online advisory enrichment via the OSV (Open Source Vulnerabilities) API.
//!
//! Endpoint: `POST https://api.osv.dev/v1/query`
//! Docs: https://google.github.io/osv.dev/api/
//!
//! Used as a fallback when the detected service has no offline cache entry.
//! Results are converted to `VulnerabilityCandidate` records and returned to
//! the calling `VulnerabilityIntelService` for inclusion in `DiscoveryQuery`.

use physarum_llm::types::VulnerabilityCandidate;
use serde::{Deserialize, Serialize};

use super::{VulnerabilityIntelInput, cache::{to_candidate, AdvisoryEntry}};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

// ── OSV request/response types ────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvQueryRequest<'a> {
    version: &'a str,
    package: OsvPackage<'a>,
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<&'a str>,
}

#[derive(Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Deserialize, Default)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize, Default)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Deserialize, Default)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Deserialize)]
struct OsvReference {
    url: String,
}

// ── Ecosystem mapping ─────────────────────────────────────────────────────────

/// Map service name to the most likely OSV ecosystem for a first-pass query.
///
/// If no specific ecosystem is known, we omit it so OSV searches across all
/// ecosystems — broader but slower.
fn ecosystem_for(service: &str) -> Option<&'static str> {
    match service {
        "nginx" | "apache-httpd" | "lighttpd" | "caddy" => Some("Bitnami"),
        "openssh" | "openssl" => None,
        "tomcat" => Some("Maven"),
        "jenkins" => Some("Maven"),
        "redis" => Some("Bitnami"),
        "wordpress" => Some("Packagist"),
        _ => None,
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Query the OSV API for advisories affecting `input.service` at `input.version`.
///
/// Returns at most `MAX_OSV_RESULTS` candidates. The call is bounded by the
/// client's configured timeout set in `VulnerabilityIntelService::new()`.
pub async fn query_osv(
    client: &reqwest::Client,
    input: &VulnerabilityIntelInput,
) -> anyhow::Result<Vec<VulnerabilityCandidate>> {
    const MAX_OSV_RESULTS: usize = 5;

    // Map service name to OSV package name (some services need name adjustment)
    let package_name = osv_package_name(&input.service);
    let ecosystem = ecosystem_for(&input.service);

    let body = OsvQueryRequest {
        version: &input.version,
        package: OsvPackage {
            name: &package_name,
            ecosystem,
        },
    };

    tracing::debug!(
        service = %input.service,
        package = %package_name,
        version = %input.version,
        ?ecosystem,
        "OSV API query"
    );

    let resp = client
        .post(OSV_QUERY_URL)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    let osv_resp: OsvQueryResponse = resp.json().await?;

    let candidates = osv_resp
        .vulns
        .into_iter()
        .take(MAX_OSV_RESULTS)
        .map(|v| osv_vuln_to_candidate(v, input))
        .collect();

    Ok(candidates)
}

fn osv_package_name(service: &str) -> String {
    match service {
        "apache-httpd" => "httpd".to_string(),
        other => other.to_string(),
    }
}

/// Convert an OSV `OsvVuln` to a `VulnerabilityCandidate`.
fn osv_vuln_to_candidate(vuln: OsvVuln, input: &VulnerabilityIntelInput) -> VulnerabilityCandidate {
    let cvss_score = extract_cvss_score(&vuln.severity);
    let fixed_version = extract_fixed_version(&vuln.affected);
    let affected_range = fixed_version
        .as_ref()
        .map(|f| format!("< {f}"))
        .unwrap_or_else(|| "unknown".to_string());

    let references: Vec<String> = vuln.references.iter().map(|r| r.url.clone()).collect();

    // Build an AdvisoryEntry-like structure and reuse to_candidate
    let entry = AdvisoryEntry {
        advisory_id: vuln.id.clone(),
        fixed_version: fixed_version.unwrap_or_default(),
        affected_range,
        cvss_score: cvss_score.unwrap_or(0.0),
        severity: cvss_to_severity(cvss_score),
        description: if vuln.summary.is_empty() {
            vuln.details.chars().take(256).collect()
        } else {
            vuln.summary
        },
        impact: vuln.details.chars().take(256).collect(),
        exploit_class: "Unknown".to_string(),
        preconditions: vec![],
        references,
    };

    to_candidate(&entry, input, true)
}

/// Extract the CVSS base score from OSV severity array.
///
/// Supports CVSS_V3 and CVSS_V2 vectors. Returns `None` when no parseable
/// score is found.
fn extract_cvss_score(severity: &[OsvSeverity]) -> Option<f32> {
    for s in severity {
        if s.severity_type.contains("CVSS") {
            // CVSS vector: "CVSS:3.1/AV:N/AC:L/.../A:H" — score is not in the vector.
            // OSV also sometimes includes a plain float score field.
            // Try parsing the score field directly as f32.
            if let Ok(score) = s.score.parse::<f32>() {
                return Some(score);
            }
            // Some entries use a CVSS vector string in the score field.
            // In that case we cannot extract the numeric score from the vector
            // without a full CVSS library — return None for those.
        }
    }
    None
}

fn cvss_to_severity(score: Option<f32>) -> String {
    match score {
        Some(s) if s >= 9.0 => "Critical",
        Some(s) if s >= 7.0 => "High",
        Some(s) if s >= 4.0 => "Medium",
        Some(s) if s > 0.0 => "Low",
        _ => "Unknown",
    }
    .to_string()
}

/// Extract the earliest `fixed` version from OSV affected ranges.
fn extract_fixed_version(affected: &[OsvAffected]) -> Option<String> {
    for aff in affected {
        for range in &aff.ranges {
            if range.range_type == "SEMVER" || range.range_type == "ECOSYSTEM" {
                for event in &range.events {
                    if let Some(fixed) = &event.fixed {
                        return Some(fixed.clone());
                    }
                }
            }
        }
    }
    None
}

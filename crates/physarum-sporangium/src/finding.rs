use crate::{extractor::ExtractedFact, template::PatternProtocol, template::SeverityHint};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// How this pattern-matching evidence was obtained.
///
/// Kept independent from `physarum_scanner::EvidenceSource`.
/// The bridge to `physarum_llm::DiscoveryQuery` is out of scope for first PR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Pattern matched via HTTP probe.
    HttpProbe,
    /// Pattern matched via raw TCP probe.
    TcpProbe,
    /// Derived from a static/offline analysis (no network I/O).
    Static,
}

/// The output of a successful template match — structured evidence fed to
/// `physarum-llm` `DiscoveryQuery` in a later PR.
///
/// Conceptual mapping to Nuclei `ResultEvent`:
/// - `template_id`              → `template_id`
/// - `name`                     → `info.name`
/// - `severity_hint`            → `info.severity`
/// - `matched_condition_summary` → `matcher_name` + matched snippets
/// - `extracted_facts`           → `extracted_results` (name → values)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternFinding {
    /// Template that produced this finding (unique identifier).
    pub template_id: String,
    /// Alias for `template_id` — kept for DiscoveryQuery bridge compatibility.
    pub check_id: String,
    /// Human-readable name from `TemplateInfo::name`.
    pub name: String,
    pub target_ip: IpAddr,
    pub port: u16,
    pub protocol: PatternProtocol,
    pub severity_hint: SeverityHint,
    /// 0.0–1.0. Currently 1.0 when all required matchers pass; future versions
    /// may weight partial matches.
    pub confidence: f32,
    /// Short summary of which matchers fired and what they matched.
    pub matched_condition_summary: String,
    /// Values extracted by the template's extractors.
    pub extracted_facts: Vec<ExtractedFact>,
    pub evidence_source: EvidenceSource,
    pub timestamp: DateTime<Utc>,
    /// CVSS score from the template's info block, if present.
    /// Propagated to PhysarumSpore candidates so ranking uses the template's
    /// declared score instead of defaulting to 5.0.
    pub template_cvss: Option<f32>,
}

impl PatternFinding {
    /// True if this finding is worth surfacing to the LLM reasoning loop.
    /// Currently: severity >= Low and confidence >= 0.7.
    pub fn is_actionable(&self) -> bool {
        self.confidence >= 0.7
            && !matches!(
                self.severity_hint,
                SeverityHint::Info | SeverityHint::Unknown
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: SeverityHint, confidence: f32) -> PatternFinding {
        PatternFinding {
            template_id: "test-id".into(),
            check_id: "test-id".into(),
            name: "Test Check".into(),
            target_ip: "127.0.0.1".parse().unwrap(),
            port: 80,
            protocol: PatternProtocol::Http,
            severity_hint: severity,
            confidence,
            matched_condition_summary: "words=['nginx']".into(),
            extracted_facts: vec![],
            evidence_source: EvidenceSource::HttpProbe,
            timestamp: Utc::now(),
            template_cvss: None,
        }
    }

    #[test]
    fn high_severity_high_confidence_is_actionable() {
        assert!(make_finding(SeverityHint::High, 1.0).is_actionable());
    }

    #[test]
    fn info_severity_never_actionable() {
        assert!(!make_finding(SeverityHint::Info, 1.0).is_actionable());
    }

    #[test]
    fn low_confidence_is_not_actionable() {
        assert!(!make_finding(SeverityHint::High, 0.5).is_actionable());
    }

    #[test]
    fn medium_severity_at_threshold_is_actionable() {
        assert!(make_finding(SeverityHint::Medium, 0.7).is_actionable());
    }
}

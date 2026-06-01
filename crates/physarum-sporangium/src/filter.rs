//! Template filtering — mirrors Nuclei's `-id`, `-tags`, `-severity`,
//! `-exclude-id`, `-exclude-tags`, `-exclude-severity` CLI flags.
//!
//! All include-filters are *inclusive OR within the set, AND across sets*:
//! a template must satisfy every non-empty include filter to be retained.
//! Exclude filters are applied after includes; any match drops the template.

use physarum_sporangium::{PatternTemplate, SeverityHint};

/// Parsed severity filter. Converts CLI strings like "info,low,medium" into
/// a `Vec<SeverityHint>`, ignoring unrecognised tokens with a warning.
pub fn parse_severities(raw: &str) -> Vec<SeverityHint> {
    raw.split(',')
        .filter_map(|s| match s.trim().to_lowercase().as_str() {
            "info" => Some(SeverityHint::Info),
            "low" => Some(SeverityHint::Low),
            "medium" | "med" => Some(SeverityHint::Medium),
            "high" => Some(SeverityHint::High),
            "critical" | "crit" => Some(SeverityHint::Critical),
            "unknown" => Some(SeverityHint::Unknown),
            other => {
                eprintln!("[WRN] unknown severity filter '{other}' — ignored");
                None
            }
        })
        .collect()
}

/// Splits a comma-separated CLI string into a normalised Vec<String>.
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',').map(|s| s.trim().to_lowercase()).collect()
}

// ─────────────────────────────────────────────────────────────────────────────

/// Stateless template filter constructed from CLI flags.
#[derive(Debug, Default)]
pub struct TemplateFilter {
    /// Include only templates whose id is in this set (empty = all).
    pub ids: Vec<String>,
    /// Include only templates that carry at least one of these tags (empty = all).
    pub tags: Vec<String>,
    /// Include only templates whose severity is in this set (empty = all).
    pub severities: Vec<SeverityHint>,

    /// Drop templates whose id appears here (applied after includes).
    pub exclude_ids: Vec<String>,
    /// Drop templates that carry any of these tags (applied after includes).
    pub exclude_tags: Vec<String>,
    /// Drop templates whose severity appears here (applied after includes).
    pub exclude_severities: Vec<SeverityHint>,
}

impl TemplateFilter {
    /// Run the filter over `templates`, returning only the matching subset.
    pub fn apply(&self, templates: Vec<PatternTemplate>) -> Vec<PatternTemplate> {
        templates.into_iter().filter(|t| self.matches(t)).collect()
    }

    fn matches(&self, t: &PatternTemplate) -> bool {
        let id_lower = t.id.to_lowercase();
        let tags_lower: Vec<String> = t.info.tags.iter().map(|s| s.to_lowercase()).collect();

        // ── include filters (empty = no restriction) ──────────────────────────
        if !self.ids.is_empty() && !self.ids.contains(&id_lower) {
            return false;
        }
        if !self.tags.is_empty() && !self.tags.iter().any(|tag| tags_lower.contains(tag)) {
            return false;
        }
        if !self.severities.is_empty() && !self.severities.contains(&t.info.severity) {
            return false;
        }

        // ── exclude filters ───────────────────────────────────────────────────
        if self.exclude_ids.contains(&id_lower) {
            return false;
        }
        if self.exclude_tags.iter().any(|tag| tags_lower.contains(tag)) {
            return false;
        }
        if self.exclude_severities.contains(&t.info.severity) {
            return false;
        }

        true
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_sporangium::{
        matcher::MatchCondition,
        template::{HttpCheck, PatternProtocol, PatternTemplate, TemplateInfo},
    };

    fn stub(id: &str, severity: SeverityHint, tags: &[&str]) -> PatternTemplate {
        PatternTemplate {
            id: id.into(),
            info: TemplateInfo {
                name: id.into(),
                authors: vec![],
                description: None,
                severity,
                tags: tags.iter().map(|s| s.to_string()).collect(),
                references: vec![],
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec![],
            },
            protocol: PatternProtocol::Http,
            http_check: Some(HttpCheck::get("/")),
            tcp_request: None,
            dns_request: None,
            ssl_request: None,
            websocket_request: None,
            matchers: vec![],
            matchers_condition: MatchCondition::Or,
            extractors: vec![],
            stop_at_first_match: false,
        }
    }

    fn catalog() -> Vec<PatternTemplate> {
        vec![
            stub(
                "nginx-server-detect",
                SeverityHint::Info,
                &["detect", "server"],
            ),
            stub("php-detect", SeverityHint::Info, &["detect", "tech"]),
            stub(
                "missing-xfo",
                SeverityHint::Low,
                &["detect", "security-headers"],
            ),
            stub(
                "http-auth-required",
                SeverityHint::Medium,
                &["detect", "auth"],
            ),
        ]
    }

    #[test]
    fn no_filters_returns_all() {
        let f = TemplateFilter::default();
        assert_eq!(f.apply(catalog()).len(), 4);
    }

    #[test]
    fn id_filter_narrows_to_one() {
        let f = TemplateFilter {
            ids: vec!["nginx-server-detect".into()],
            ..Default::default()
        };
        let out = f.apply(catalog());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "nginx-server-detect");
    }

    #[test]
    fn tag_filter_server_returns_one() {
        let f = TemplateFilter {
            tags: vec!["server".into()],
            ..Default::default()
        };
        assert_eq!(f.apply(catalog()).len(), 1);
    }

    #[test]
    fn severity_filter_low_returns_one() {
        let f = TemplateFilter {
            severities: vec![SeverityHint::Low],
            ..Default::default()
        };
        assert_eq!(f.apply(catalog()).len(), 1);
    }

    #[test]
    fn exclude_id_drops_one() {
        let f = TemplateFilter {
            exclude_ids: vec!["php-detect".into()],
            ..Default::default()
        };
        assert_eq!(f.apply(catalog()).len(), 3);
    }

    #[test]
    fn exclude_severity_info_drops_two() {
        let f = TemplateFilter {
            exclude_severities: vec![SeverityHint::Info],
            ..Default::default()
        };
        assert_eq!(f.apply(catalog()).len(), 2);
    }

    #[test]
    fn exclude_tag_security_headers_drops_one() {
        let f = TemplateFilter {
            exclude_tags: vec!["security-headers".into()],
            ..Default::default()
        };
        assert_eq!(f.apply(catalog()).len(), 3);
    }

    #[test]
    fn parse_severities_roundtrip() {
        let v = parse_severities("info,low,MEDIUM,High,critical");
        assert_eq!(
            v,
            vec![
                SeverityHint::Info,
                SeverityHint::Low,
                SeverityHint::Medium,
                SeverityHint::High,
                SeverityHint::Critical,
            ]
        );
    }
}

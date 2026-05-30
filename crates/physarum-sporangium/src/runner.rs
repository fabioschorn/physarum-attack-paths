use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::finding::{EvidenceSource, PatternFinding};
use crate::matcher::{MatchCondition, PatternMatcher};
use crate::policy::RunPolicy;
use crate::template::{HttpMethod, PatternTemplate};

/// In-memory HTTP response snapshot used during pattern evaluation.
/// Body is capped at `RunPolicy::max_response_bytes` before any matching occurs.
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status: u16,
    /// Header names are lowercased for case-insensitive lookup.
    pub headers: HashMap<String, String>,
    /// Truncated at RunPolicy::max_response_bytes.
    pub body: String,
}

/// Bounded, allowlist-enforced pattern-matching runner.
///
/// Workflow per invocation:
/// 1. `policy.check_allowed(template.id)` — reject if not in allowlist
/// 2. `execute_http()` — send the HTTP probe, cap response body
/// 3. `evaluate_template()` — apply matchers + extractors (no I/O)
/// 4. Return `Vec<PatternFinding>` (empty when no matcher fires)
pub struct PatternRunner {
    client: reqwest::Client,
    policy: RunPolicy,
}

impl PatternRunner {
    pub fn new(policy: RunPolicy) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(policy.request_timeout_ms))
            .redirect(reqwest::redirect::Policy::limited(
                policy.max_redirects as usize,
            ))
            .build()
            .context("build reqwest client for PatternRunner")?;
        Ok(Self { client, policy })
    }

    /// Run a template against a target (ip, port). Returns findings (empty = no match).
    pub async fn run(
        &self,
        template: &PatternTemplate,
        target_ip: IpAddr,
        port: u16,
    ) -> Result<Vec<PatternFinding>> {
        self.policy.check_allowed(&template.id)?;

        let check = match &template.http_check {
            Some(c) => c,
            None => {
                tracing::warn!(
                    template_id = %template.id,
                    "template has no http_check — skipping"
                );
                return Ok(vec![]);
            }
        };

        let resp = self
            .execute_http(check, target_ip, port)
            .await
            .with_context(|| {
                format!(
                    "template '{}': HTTP probe against {}:{}",
                    template.id, target_ip, port
                )
            })?;

        Ok(evaluate_template(
            template,
            &resp,
            target_ip,
            port,
            EvidenceSource::HttpProbe,
        ))
    }

    async fn execute_http(
        &self,
        check: &crate::template::HttpCheck,
        target_ip: IpAddr,
        port: u16,
    ) -> Result<ResponseData> {
        let scheme = if port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, target_ip, port, check.path);

        let method = match check.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        };

        let mut req = self.client.request(method, &url);
        for (k, v) in &check.headers {
            req = req.header(k, v);
        }
        if let Some(body) = &check.body {
            req = req.body(body.clone());
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("HTTP request to {url}"))?;

        let status = resp.status().as_u16();
        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        let max_bytes = check
            .max_response_bytes
            .unwrap_or(self.policy.max_response_bytes);

        let bytes = resp.bytes().await.context("read response body")?;
        let truncated = &bytes[..bytes.len().min(max_bytes)];
        let body = String::from_utf8_lossy(truncated).into_owned();

        tracing::debug!(
            url = %url,
            status,
            body_bytes = truncated.len(),
            "HTTP probe complete"
        );

        Ok(ResponseData {
            status,
            headers,
            body,
        })
    }
}

/// Pure function: evaluate a template's matchers and extractors against a
/// pre-built `ResponseData`. No network I/O. Exported so tests can call it
/// directly without spinning up a real HTTP server.
pub fn evaluate_template(
    template: &PatternTemplate,
    resp: &ResponseData,
    target_ip: IpAddr,
    port: u16,
    evidence_source: EvidenceSource,
) -> Vec<PatternFinding> {
    let (overall_match, summary) =
        apply_matchers(&template.matchers, template.matchers_condition, resp);

    if !overall_match {
        return vec![];
    }

    let extracted_facts = template
        .extractors
        .iter()
        .map(|ex| ex.apply(resp))
        .filter(|fact| !fact.values.is_empty())
        .collect();

    vec![PatternFinding {
        template_id: template.id.clone(),
        check_id: template.id.clone(),
        name: template.info.name.clone(),
        target_ip,
        port,
        protocol: template.protocol,
        severity_hint: template.info.severity,
        confidence: 1.0,
        matched_condition_summary: summary,
        extracted_facts,
        evidence_source,
        timestamp: Utc::now(),
    }]
}

fn apply_matchers(
    matchers: &[PatternMatcher],
    condition: MatchCondition,
    resp: &ResponseData,
) -> (bool, String) {
    if matchers.is_empty() {
        return (true, "no matchers".into());
    }

    let results: Vec<(bool, String, &str)> = matchers
        .iter()
        .map(|m| {
            let (matched, snippet) = m.apply(resp);
            (matched, snippet, m.name.as_str())
        })
        .collect();

    let overall = match condition {
        MatchCondition::And => results.iter().all(|(m, _, _)| *m),
        MatchCondition::Or => results.iter().any(|(m, _, _)| *m),
    };

    let summary = results
        .iter()
        .filter(|(matched, _, _)| *matched)
        .map(|(_, snippet, name)| format!("{name}: {snippet}"))
        .collect::<Vec<_>>()
        .join("; ");

    (
        overall,
        if summary.is_empty() {
            "no matchers fired".into()
        } else {
            summary
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractor::{ExtractPart, ExtractorType, PatternExtractor};
    use crate::matcher::{MatchPart, MatcherType, PatternMatcher};
    use crate::template::{
        HttpCheck, PatternProtocol, PatternTemplate, SeverityHint, TemplateInfo,
    };

    fn nginx_detect_template() -> PatternTemplate {
        PatternTemplate {
            id: "nginx-server-detect".into(),
            info: TemplateInfo {
                name: "Nginx Server Detection".into(),
                authors: vec!["physarum".into()],
                description: Some("Detects nginx via Server response header".into()),
                severity: SeverityHint::Info,
                tags: vec!["detect".into(), "nginx".into()],
                references: vec![],
            },
            protocol: PatternProtocol::Http,
            http_check: Some(HttpCheck::get("/")),
            matchers: vec![PatternMatcher {
                name: "nginx-header".into(),
                matcher_type: MatcherType::Words {
                    words: vec!["nginx".into()],
                    case_insensitive: true,
                    all_must_match: false,
                },
                part: MatchPart::Headers,
                negate: false,
            }],
            matchers_condition: MatchCondition::Or,
            extractors: vec![PatternExtractor {
                name: "server-version".into(),
                extractor_type: ExtractorType::Regex {
                    pattern: r"nginx/[\d.]+".into(),
                    group: 0,
                },
                part: ExtractPart::Headers,
                internal: false,
            }],
            stop_at_first_match: true,
        }
    }

    fn http_status_ok_template() -> PatternTemplate {
        PatternTemplate {
            id: "http-status-ok".into(),
            info: TemplateInfo {
                name: "HTTP 200 OK".into(),
                authors: vec!["physarum".into()],
                description: Some("Confirms host returns HTTP 200".into()),
                severity: SeverityHint::Info,
                tags: vec!["detect".into()],
                references: vec![],
            },
            protocol: PatternProtocol::Http,
            http_check: Some(HttpCheck::get("/")),
            matchers: vec![PatternMatcher {
                name: "status-200".into(),
                matcher_type: MatcherType::Status { codes: vec![200] },
                part: MatchPart::Status,
                negate: false,
            }],
            matchers_condition: MatchCondition::Or,
            extractors: vec![],
            stop_at_first_match: false,
        }
    }

    fn make_resp(status: u16, headers: &[(&str, &str)], body: &str) -> ResponseData {
        ResponseData {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
        }
    }

    #[test]
    fn nginx_detect_fires_on_nginx_header() {
        let template = nginx_detect_template();
        let resp = make_resp(200, &[("server", "nginx/1.25.3")], "<html/>");
        let ip: IpAddr = "172.20.0.3".parse().unwrap();

        let findings = evaluate_template(&template, &resp, ip, 80, EvidenceSource::HttpProbe);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "nginx-server-detect");
        assert!(findings[0]
            .matched_condition_summary
            .contains("nginx-header"));
    }

    #[test]
    fn nginx_detect_extracts_version() {
        let template = nginx_detect_template();
        let resp = make_resp(200, &[("server", "nginx/1.25.3")], "");
        let ip: IpAddr = "172.20.0.3".parse().unwrap();

        let findings = evaluate_template(&template, &resp, ip, 80, EvidenceSource::HttpProbe);
        assert_eq!(findings.len(), 1);
        let fact = findings[0]
            .extracted_facts
            .iter()
            .find(|f| f.name == "server-version")
            .expect("server-version fact must be present");
        assert_eq!(fact.values, vec!["nginx/1.25.3"]);
    }

    #[test]
    fn nginx_detect_silent_on_apache() {
        let template = nginx_detect_template();
        let resp = make_resp(200, &[("server", "Apache/2.4.58")], "");
        let ip: IpAddr = "172.20.0.3".parse().unwrap();

        let findings = evaluate_template(&template, &resp, ip, 80, EvidenceSource::HttpProbe);
        assert!(findings.is_empty());
    }

    #[test]
    fn http_status_ok_fires_on_200() {
        let template = http_status_ok_template();
        let resp = make_resp(200, &[], "");
        let ip: IpAddr = "172.20.0.2".parse().unwrap();

        let findings = evaluate_template(&template, &resp, ip, 80, EvidenceSource::HttpProbe);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn http_status_ok_silent_on_404() {
        let template = http_status_ok_template();
        let resp = make_resp(404, &[], "");
        let ip: IpAddr = "172.20.0.2".parse().unwrap();

        let findings = evaluate_template(&template, &resp, ip, 80, EvidenceSource::HttpProbe);
        assert!(findings.is_empty());
    }

    #[test]
    fn and_condition_requires_all_matchers() {
        let template = PatternTemplate {
            id: "and-check".into(),
            info: TemplateInfo {
                name: "AND Check".into(),
                authors: vec![],
                description: None,
                severity: SeverityHint::Low,
                tags: vec![],
                references: vec![],
            },
            protocol: PatternProtocol::Http,
            http_check: Some(HttpCheck::get("/")),
            matchers: vec![
                PatternMatcher {
                    name: "status-200".into(),
                    matcher_type: MatcherType::Status { codes: vec![200] },
                    part: MatchPart::Status,
                    negate: false,
                },
                PatternMatcher {
                    name: "body-hello".into(),
                    matcher_type: MatcherType::Words {
                        words: vec!["hello".into()],
                        case_insensitive: true,
                        all_must_match: false,
                    },
                    part: MatchPart::Body,
                    negate: false,
                },
            ],
            matchers_condition: MatchCondition::And,
            extractors: vec![],
            stop_at_first_match: false,
        };

        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Both conditions met
        let both = make_resp(200, &[], "hello world");
        assert_eq!(
            evaluate_template(&template, &both, ip, 80, EvidenceSource::HttpProbe).len(),
            1
        );

        // Only status matches
        let only_status = make_resp(200, &[], "goodbye");
        assert!(
            evaluate_template(&template, &only_status, ip, 80, EvidenceSource::HttpProbe)
                .is_empty()
        );
    }

    #[test]
    fn validate_catches_invalid_regex_in_template() {
        let mut template = nginx_detect_template();
        template.extractors.push(PatternExtractor {
            name: "bad".into(),
            extractor_type: ExtractorType::Regex {
                pattern: "[invalid".into(),
                group: 0,
            },
            part: ExtractPart::Body,
            internal: false,
        });
        assert!(template.validate().is_err());
    }
}

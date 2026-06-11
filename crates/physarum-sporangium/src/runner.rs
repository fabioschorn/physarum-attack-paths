use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::finding::{EvidenceSource, PatternFinding};
use crate::matcher::{MatchCondition, PatternMatcher};
use crate::policy::RunPolicy;
use crate::template::{HttpMethod, PatternTemplate};

/// In-memory response snapshot used during pattern evaluation.
///
/// Covers HTTP, TCP, DNS, SSL, and WebSocket protocols.
/// Body is capped at `RunPolicy::max_response_bytes` for HTTP; for other
/// protocols the `extra` map carries protocol-specific fields.
#[derive(Debug, Clone, Default)]
pub struct ResponseData {
    /// HTTP status code (0 for non-HTTP protocols).
    pub status: u16,
    /// Header names are lowercased for case-insensitive lookup.
    pub headers: HashMap<String, String>,
    /// Response body text (UTF-8 lossy conversion from raw bytes).
    /// Truncated at RunPolicy::max_response_bytes for HTTP.
    pub body: String,
    /// Raw bytes — used by Binary matcher and TCP/network protocol.
    pub raw_bytes: Option<Vec<u8>>,
    /// Protocol-specific fields (DNS sections, SSL certificate fields, etc.).
    /// Keys are lowercase snake_case (e.g. "answer", "certificate", "cipher").
    pub extra: HashMap<String, String>,
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
    ///
    /// `scheme_hint` overrides port-based scheme detection when the caller has
    /// stronger evidence (e.g. from a banner grab or `SensingResult.scheme_hint`).
    /// Pass `Some("https")` or `Some("http")` to force a scheme; `None` falls
    /// back to port-based detection (443/8443/9443 → https, else http).
    pub async fn run(
        &self,
        template: &PatternTemplate,
        target_ip: IpAddr,
        port: u16,
        scheme_hint: Option<&str>,
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
            .execute_http(check, target_ip, port, scheme_hint)
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

    /// Run a TCP template against a non-web port. Returns findings (empty = no match or no tcp_request).
    ///
    /// Delegates to `tcp::run_tcp()` — handles raw byte exchange, banner grabbing,
    /// matchers, and extractors. Use for `ConfirmedNonWeb` ports (FTP, SMTP, POP3, IMAP, …)
    /// where HTTP probing is not applicable. Connection and exchange timeouts are
    /// taken from `RunPolicy::request_timeout_ms`.
    pub async fn run_tcp_template(
        &self,
        template: &PatternTemplate,
        target_ip: IpAddr,
        port: u16,
    ) -> Result<Vec<PatternFinding>> {
        self.policy.check_allowed(&template.id)?;
        crate::tcp::run_tcp(
            template,
            target_ip,
            port,
            &Default::default(),
            self.policy.request_timeout_ms,
        )
        .await
    }

    async fn execute_http(
        &self,
        check: &crate::template::HttpCheck,
        target_ip: IpAddr,
        port: u16,
        scheme_hint: Option<&str>,
    ) -> Result<ResponseData> {
        let scheme = match scheme_hint {
            Some("https") => "https",
            Some("http") => "http",
            // Caller provided no scheme evidence — fall back to port convention.
            // Non-standard TLS ports (e.g. 10443, custom admin panels) may produce
            // silent misses here. Pass scheme_hint from SensingResult to avoid this.
            _ => {
                if matches!(port, 443 | 8443 | 9443) {
                    "https"
                } else {
                    "http"
                }
            }
        };
        let url = format!("{}://{}:{}{}", scheme, target_ip, port, check.path);

        let method = match check.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
            HttpMethod::Patch => reqwest::Method::PATCH,
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
            raw_bytes: None,
            extra: Default::default(),
        })
    }
}

/// Evaluate a template's HTTP matchers and extractors against a
/// pre-built `ResponseData`. No network I/O.
///
/// Uses the HTTP-specific matchers and extractors (top-level `matchers` /
/// `extractors` fields). For non-HTTP protocols use
/// [`evaluate_template_with_response`] which routes to protocol-specific fields.
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
        template_cvss: template.info.cvss_score,
    }]
}

/// Evaluate a template using the effective matchers/extractors for its protocol.
///
/// Routes to the correct matcher/extractor set based on `template.protocol`:
/// - HTTP → `template.matchers` / `template.extractors`
/// - TCP/DNS/SSL/WebSocket → protocol-specific request matchers/extractors
pub fn evaluate_template_with_response(
    template: &PatternTemplate,
    resp: &ResponseData,
    target_ip: IpAddr,
    port: u16,
    evidence_source: EvidenceSource,
) -> Vec<PatternFinding> {
    let matchers = template.effective_matchers();
    let condition = template.effective_matchers_condition();
    let extractors = template.effective_extractors();

    let (overall_match, summary) = apply_matchers(matchers, condition, resp);

    if !overall_match {
        return vec![];
    }

    let extracted_facts = extractors
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
        template_cvss: template.info.cvss_score,
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

    fn ti(name: &str, severity: SeverityHint) -> TemplateInfo {
        TemplateInfo {
            name: name.into(),
            authors: vec!["physarum".into()],
            description: None,
            severity,
            tags: vec![],
            references: vec![],
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
        }
    }

    fn http_tmpl(
        id: &str,
        info: TemplateInfo,
        matchers: Vec<PatternMatcher>,
        condition: MatchCondition,
        extractors: Vec<PatternExtractor>,
        stop: bool,
    ) -> PatternTemplate {
        PatternTemplate {
            id: id.into(),
            info,
            protocol: PatternProtocol::Http,
            http_check: Some(HttpCheck::get("/")),
            tcp_request: None,
            dns_request: None,
            ssl_request: None,
            websocket_request: None,
            matchers,
            matchers_condition: condition,
            extractors,
            stop_at_first_match: stop,
        }
    }

    fn nginx_detect_template() -> PatternTemplate {
        http_tmpl(
            "nginx-server-detect",
            ti("Nginx Server Detection", SeverityHint::Info),
            vec![PatternMatcher {
                name: "nginx-header".into(),
                matcher_type: MatcherType::Words {
                    words: vec!["nginx".into()],
                    case_insensitive: true,
                    all_must_match: false,
                },
                part: MatchPart::Headers,
                negate: false,
            }],
            MatchCondition::Or,
            vec![PatternExtractor {
                name: "server-version".into(),
                extractor_type: ExtractorType::Regex {
                    pattern: r"nginx/[\d.]+".into(),
                    group: 0,
                },
                part: ExtractPart::Headers,
                internal: false,
            }],
            true,
        )
    }

    fn http_status_ok_template() -> PatternTemplate {
        http_tmpl(
            "http-status-ok",
            ti("HTTP 200 OK", SeverityHint::Info),
            vec![PatternMatcher {
                name: "status-200".into(),
                matcher_type: MatcherType::Status { codes: vec![200] },
                part: MatchPart::Status,
                negate: false,
            }],
            MatchCondition::Or,
            vec![],
            false,
        )
    }

    fn make_resp(status: u16, headers: &[(&str, &str)], body: &str) -> ResponseData {
        ResponseData {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            raw_bytes: None,
            extra: Default::default(),
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
        let template = http_tmpl(
            "and-check",
            ti("AND Check", SeverityHint::Low),
            vec![
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
            MatchCondition::And,
            vec![],
            false,
        );

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

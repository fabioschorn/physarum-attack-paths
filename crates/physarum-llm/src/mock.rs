use std::sync::Arc;

use crate::{
    client::QueryFuture,
    types::{ArtifactType, DiscoveryQuery, PropagationMethod, PropagationStrategy},
    LlmClient,
};

/// Deterministic LLM client for testing and Docker Lab validation.
///
/// Returns a preset `PropagationStrategy` on every call — no network,
/// no API key, no external dependency. Used in:
///   - unit and integration tests
///   - Docker Lab Phase 3 validation
///   - CI runs where a real LLM endpoint is not available
///
/// The strategy can be configured at construction time. Use the
/// builder methods for common scenarios.
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

    /// Returns an HTTP strategy for a given path.
    pub fn http_get(path: impl Into<String>, confidence: f32) -> Self {
        let p = path.into();
        Self::new(PropagationStrategy {
            method: PropagationMethod::Http {
                path: p.clone(),
                http_method: crate::types::HttpMethod::Get,
                headers: vec![],
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
}

impl LlmClient for MockLlmClient {
    fn query_propagation<'a>(&'a self, _query: &'a DiscoveryQuery) -> QueryFuture<'a> {
        let strategy = Arc::clone(&self.strategy);
        Box::pin(async move { Ok((*strategy).clone()) })
    }
}

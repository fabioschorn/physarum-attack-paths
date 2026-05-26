use std::net::IpAddr;
use serde::{Deserialize, Serialize};

// ── Scanner fingerprint ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScan {
    pub port: u16,
    pub protocol: TransportProtocol,
    pub state: PortState,
    pub service_guess: Option<String>,
    pub banner: Option<String>,
    pub version_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Filtered,
    Closed,
}

/// Best-effort OS hint derived from banners and handshakes only.
/// No raw sockets or CAP_NET_RAW required (Manager decision Gap 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsHint {
    pub guess: String,
    pub confidence: f32,
    pub source: OsHintSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OsHintSource {
    SshBanner,
    HttpHeader,
    ServiceBanner,
    Convention,
}

// ── Discovery query ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryQuery {
    pub target: IpAddr,
    pub ports: Vec<PortScan>,
    pub os_hint: Option<OsHint>,
    pub lineage_summary: LineageSummary,
    pub methods_tried: Vec<String>,
    /// Strategies rejected by the policy gate on previous attempts.
    /// Fed back to the LLM so it does not re-propose blocked methods (Gap 1).
    pub rejected_strategies: Vec<RejectedStrategy>,
    pub attempt_number: u8,
}

/// Minimal lineage context sent to the LLM — no secrets, no raw payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageSummary {
    pub node_id: String,
    pub hop_count: u8,
    pub current_score: f32,
    pub colonized_count: usize,
}

// ── Rejected strategy feedback (Gap 1 resolution) ────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedStrategy {
    pub attempt_number: u8,
    pub method_class: PropagationMethodClass,
    pub rejection_reason: PolicyRejectionReason,
    pub policy_rule: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropagationMethodClass {
    Ssh,
    Http,
    Exploit,
    Custom,
    NoPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRejectionReason {
    MethodNotAllowed,
    ConfidenceBelowThreshold,
    TargetOutsideAllowedCidr,
    MaxAttemptsExceeded,
    SecretMaterialDetected,
    ArtifactTypeNotAllowed,
    ExploitNotEnabledForLabMode,
    Custom(String),
}

// ── Propagation strategy ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationStrategy {
    pub method: PropagationMethod,
    pub artifact_type: ArtifactType,
    pub bootstrap_plan: Option<BootstrapPlan>,
    pub confidence: f32,
    pub reasoning_summary: String,
    pub preconditions: Vec<String>,
    pub validation_check: Option<String>,
    pub safety_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropagationMethod {
    Ssh {
        user: String,
        auth: SshAuth,
    },
    Http {
        path: String,
        http_method: HttpMethod,
        headers: Vec<(String, String)>,
    },
    /// Lab-only. Disabled by default; requires explicit lab policy enablement.
    Exploit {
        cve: String,
    },
    Custom {
        description: String,
    },
    NoPath {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SshAuth {
    EmptyPassword,
    PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}

// ── Artifact type (Gap 4 resolution — typed enum) ────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    AgentBinary,
    Script,
    HttpRequest,
    None,
}

// ── Bootstrap plan (Gap 5 resolution — Option A: typed steps) ────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapPlan {
    pub steps: Vec<BootstrapStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapStep {
    pub action: BootstrapAction,
    pub target: String,
    pub timeout_ms: u64,
    pub requires_root: bool,
    pub expected_result: ExpectedResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BootstrapAction {
    HttpPost { path: String, body: String },
    HttpGet { path: String },
    ScpUpload { local_path: String, remote_path: String },
    SshCommand { command: String },
    /// Must be explicitly permitted by lab policy before execution.
    Custom { description: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedResult {
    pub success_indicator: String,
    pub failure_indicator: Option<String>,
}

// ── Lineage evidence (Gap 7 resolution — schema defined here, wired in Phase 4) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAttemptEvidence {
    pub target: String,
    pub attempt_number: u8,
    pub method_class: PropagationMethodClass,
    pub artifact_type: ArtifactType,
    pub policy_decision: PolicyDecision,
    pub execution_result: ExecutionResultSummary,
    pub reasoning_summary: String,
    pub next_action: NextAction,
    /// Stable identifier for the strategy (e.g. sha256 of the JSON).
    pub strategy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyDecision {
    Accepted,
    Rejected {
        reason: PolicyRejectionReason,
        rule: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionResultSummary {
    Success,
    Failed { description: String },
    Skipped { reason: String },
    NotAttempted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NextAction {
    RetryWithLlm,
    MarkDeadEnd,
    ContinueOrganismLoop,
    MaxAttemptsReached,
}

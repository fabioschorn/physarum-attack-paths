use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ── Secret reference ──────────────────────────────────────────────────────────

/// A reference to a secret held by the local executor.
///
/// The LLM may request a capability class (e.g. an ephemeral SSH key for
/// reverse-pull propagation) but must never emit, carry, or store the secret
/// material itself. The executor resolves this reference locally at runtime.
/// Raw PEM, credentials, or API tokens must not appear in any strategy contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    /// Short identifier for the audit trail — typically a hash of the public key.
    /// Safe to record in lineage; not the secret itself.
    pub key_id: String,
    pub source: SecretSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretSource {
    /// Executor generates the key pair locally before the RCE fires.
    RuntimeGenerated,
    /// Key exists in the local agent's secret store (reserved for future use).
    LocalAgentSecretStore,
}

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

// ── Pattern evidence summary ──────────────────────────────────────────────────

/// Condensed evidence from physarum-sporangium HTTP pattern probing.
///
/// Includes both fingerprint/context findings (e.g. server version detection,
/// info-level) and actionable risk findings (severity >= low, confidence >= 0.7).
/// Use `is_actionable = true` to distinguish higher-priority findings from
/// passive fingerprint context. Only the fields needed for propagation reasoning
/// are included; raw response bodies are never forwarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternFindingSummary {
    /// Template ID that matched (e.g. "nginx-server-detect", "missing-hsts").
    pub check_id: String,
    /// Human-readable template name.
    pub name: String,
    /// Severity level: "info" | "low" | "medium" | "high" | "critical".
    pub severity: String,
    /// Probe confidence — 0.0–1.0.
    pub confidence: f32,
    /// Short summary of which matchers fired (e.g. "words=['nginx']").
    pub matched_summary: String,
    /// Values extracted by the template (version strings, page titles, etc.).
    pub extracted: Vec<String>,
    /// True when severity >= Low and confidence >= 0.7.
    /// Signals that the LLM should treat this finding as actionable evidence.
    pub is_actionable: bool,
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
    /// One-based: first attempt is 1, last valid attempt is `max_attempts`.
    /// Values above `max_attempts` are rejected by `PolicyGate::evaluate()`.
    pub attempt_number: u8,
    /// Pattern-evidence findings from physarum-sporangium HTTP probing.
    ///
    /// Includes both fingerprint/context findings (e.g. server version, info-level)
    /// and actionable risk findings (severity >= low, confidence >= 0.7).
    /// Use `is_actionable = true` to distinguish higher-priority evidence.
    /// Empty when no web-like services are detected or sporangium enrichment fails.
    ///
    /// `default` ensures existing lineage JSON without this field deserialises
    /// cleanly — backwards-compatible with v0.3.0 and earlier lineage records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pattern_findings: Vec<PatternFindingSummary>,
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
    /// One-based attempt number at which this strategy was rejected.
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
    InvalidSecretReference,
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
        /// TCP port to target. LLM must set this from the open ports list.
        /// Defaults to 80 when absent (backward-compatible with v0.3.x lineage).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    /// Lab-only. Disabled by default; requires explicit lab policy enablement.
    Exploit {
        cve: String,
    },
    /// Disabled by default in `PolicyGate::lab_default()`.
    /// Must be explicitly enabled by lab policy configuration.
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
    HttpPost {
        path: String,
        body: String,
        /// TCP port to target. Defaults to 80 when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    HttpGet {
        path: String,
        /// TCP port to target. Defaults to 80 when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    /// A → B push (current SSH/SCP propagation path).
    ScpUpload {
        local_path: String,
        remote_path: String,
    },
    /// B → A reverse-pull propagation pattern.
    ///
    /// Used when Host B's inbound SSH blocks Host A but outbound is open.
    /// The RCE delivers a small bootstrap script to Host B. Host B connects
    /// OUT to Host A and pulls the physarum-maze binary via SCP.
    ///
    /// Key lifecycle (resolved by the executor, not the LLM):
    ///   1. Generate ephemeral ed25519 key pair before RCE fires.
    ///   2. Add public key to Host A's authorized_keys (temporary).
    ///   3. Inject private key into the bootstrap script at runtime.
    ///   4. Remove public key after propagation succeeds or times out.
    ///
    /// The LLM specifies capability class via `secret_ref`.
    /// Raw key material never travels through the strategy contract or lineage.
    ScpPullFromSource {
        source_ip: String,
        source_path: String,
        dest_path: String,
        /// Reference to the ephemeral key — not the key itself.
        /// The executor generates and injects the actual key material locally.
        secret_ref: SecretRef,
    },
    SshCommand {
        command: String,
    },
    /// Must be explicitly permitted by lab policy before execution.
    Custom {
        description: String,
    },
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
    /// One-based attempt number matching `DiscoveryQuery::attempt_number`.
    pub attempt_number: u8,
    /// Stimulus that triggered this evidence pipeline:
    /// `"startup-sensing"`, `"icmp"`, `"tcp-syn"`, `"ebpf"`, or `"discovery"`.
    pub stimulus_source: String,
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

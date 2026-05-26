/// physarum-llm — Phase 1: data contracts, LlmClient trait, policy gate, prompt template.
///
/// Phase 2: physarum-scanner enrichment (adds service/banner/os_hint fields).
/// Phase 3: OpenAiCompatibleClient + MockLlmClient implementations.
/// Phase 4: physarum-maze integration (decision loop, lineage wiring).
/// Phase 5: isolated lab validation (terraform-vuln, CVE PoC).
pub mod client;
pub mod policy;
pub mod prompt;
pub mod types;

pub use client::{LlmClient, QueryFuture};
pub use policy::{PolicyGate, MAX_ATTEMPTS, MIN_CONFIDENCE};
pub use types::{
    ArtifactType, BootstrapAction, BootstrapPlan, BootstrapStep, DiscoveryQuery,
    ExecutionResultSummary, ExpectedResult, HttpMethod, LineageSummary, LlmAttemptEvidence,
    NextAction, OsHint, OsHintSource, PolicyDecision, PolicyRejectionReason, PortScan, PortState,
    PropagationMethod, PropagationMethodClass, PropagationStrategy, RejectedStrategy, SshAuth,
    TransportProtocol,
};

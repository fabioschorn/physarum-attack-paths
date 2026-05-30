/// physarum-llm — LLM-aware propagation reasoning.
///
/// Phase 1 (merged): data contracts, LlmClient trait, PolicyGate, prompt template.
/// Phase 3 (this): MockLlmClient, OpenAiCompatibleClient, schema round-trip tests.
/// Phase 4 (next): physarum-maze integration — CLI flags, decision loop, lineage wiring.
/// Phase 2 (after): physarum-scanner enrichment — SensingProfile, richer DiscoveryQuery.
/// Phase 5 (last): Docker Lab + AWS Lab validation with CVE PoC.
pub mod client;
pub mod mock;
pub mod openai;
pub mod policy;
pub mod prompt;
pub mod schema_tests;
pub mod types;

pub use client::{LlmClient, QueryFuture};
pub use mock::MockLlmClient;
pub use openai::OpenAiCompatibleClient;
pub use policy::{PolicyGate, MAX_ATTEMPTS, MIN_CONFIDENCE};
pub use types::{
    ArtifactType, BootstrapAction, BootstrapPlan, BootstrapStep, DiscoveryQuery,
    ExecutionResultSummary, ExpectedResult, HttpMethod, LineageSummary, LlmAttemptEvidence,
    NextAction, OsHint, OsHintSource, PolicyDecision, PolicyRejectionReason, PortScan, PortState,
    PropagationMethod, PropagationMethodClass, PropagationStrategy, RejectedStrategy, SecretRef,
    SecretSource, SshAuth, TransportProtocol,
};

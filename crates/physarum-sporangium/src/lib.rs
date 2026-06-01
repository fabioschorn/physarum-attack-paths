//! `physarum-sporangium` — complete Rust port of Nuclei's detection engine.
//!
//! ## Design mapping (Nuclei → physarum-sporangium)
//!
//! | Nuclei concept               | physarum-sporangium type              |
//! |------------------------------|---------------------------------------|
//! | Template / YAML rule         | `PatternTemplate`                     |
//! | `info` block                 | `TemplateInfo`                        |
//! | Matcher (all types)          | `PatternMatcher` / `MatcherType`      |
//! | Extractor (all types)        | `PatternExtractor` / `ExtractorType`  |
//! | Severity                     | `SeverityHint`                        |
//! | ResultEvent                  | `PatternFinding`                      |
//! | Runner                       | `PatternRunner` + `RunPolicy`         |
//! | Generator (BatteringRam/...) | `PayloadGenerator` / `AttackType`     |
//! | AuthProvider                 | `AuthProvider` / `AuthStrategy`       |
//! | DSL helper functions         | `dsl::evaluate_dsl`                   |
//! | Network protocol             | `tcp::run_tcp`                        |
//! | DNS protocol                 | `dns::run_dns`                        |
//! | SSL protocol                 | `ssl::run_ssl`                        |
//! | WebSocket protocol           | `websocket::run_websocket`            |
//! | Workflow                     | `workflow::Workflow` / `WorkflowStep` |
//!
//! ## Ported capabilities
//!
//! ### Matcher types
//! `status`, `words`, `regex`, `binary` (hex), `size`, `dsl` (evalexpr),
//! `xpath` (HTML via scraper, XML via sxd-xpath)
//!
//! ### Extractor types
//! `regex` (group), `kval`, `json` (pointer), `xpath`, `dsl`
//!
//! ### Protocols
//! HTTP, TCP/Network, DNS (A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/DS/ANY),
//! SSL/TLS (certificate inspection), WebSocket (ws:// and wss://)
//!
//! ### Authentication
//! Basic, Bearer, custom Headers, Cookies, Query parameters
//!
//! ### Payload generators
//! BatteringRam, Pitchfork, ClusterBomb (file-based wordlists supported)
//!
//! ### Workflow engine
//! Multi-step template chains with matcher-gated subtemplate execution
//!
//! ## Safety invariants (enforced, not trusted)
//!
//! - Templates not in `RunPolicy::allowed_check_ids` are rejected before network I/O.
//! - Response bodies are capped at `RunPolicy::max_response_bytes` (default 64 KiB).
//! - No subprocess, no external Nuclei binary.
//! - Exploit-class checks are out of scope; this is detection only.
//! - `exploit_enabled=false` by default — candidates are contextual evidence only.

pub mod auth;
pub mod catalog;
pub mod dns;
pub mod dsl;
pub mod extractor;
pub mod finding;
pub mod generator;
pub mod matcher;
pub mod policy;
pub mod runner;
pub mod ssl;
pub mod tcp;
pub mod template;
pub mod websocket;
pub mod workflow;

// ── Flat re-exports ───────────────────────────────────────────────────────────

// Auth providers
pub use auth::{AuthProvider, AuthStrategy};

// Catalog
pub use catalog::all_templates;

// DNS
pub use dns::run_dns;

// DSL engine
pub use dsl::{build_dsl_context_from_response, evaluate_dsl, evaluate_dsl_string};

// Extractors
pub use extractor::{ExtractPart, ExtractedFact, ExtractorType, PatternExtractor};

// Findings
pub use finding::{EvidenceSource, PatternFinding};

// Payload generator
pub use generator::{apply_payload, AttackType, PayloadGenerator, PayloadSource};

// Matchers
pub use matcher::{MatchCondition, MatchPart, MatcherType, PatternMatcher};

// Policy
pub use policy::RunPolicy;

// Runner
pub use runner::{evaluate_template, evaluate_template_with_response, PatternRunner, ResponseData};

// SSL
pub use ssl::run_ssl;

// TCP
pub use tcp::run_tcp;

// Templates
pub use template::{
    DnsRecordType, DnsRequest, HttpCheck, HttpMethod, InputEncoding, PatternProtocol,
    PatternTemplate, SeverityHint, SslRequest, TcpInput, TcpRequest, TemplateInfo, TlsVersion,
    WebSocketRequest, WsInput,
};

// WebSocket
pub use websocket::run_websocket;

// Workflow
pub use workflow::{
    matcher_fires, should_run_subtemplate, Workflow, WorkflowCondition, WorkflowMatcher,
    WorkflowResult, WorkflowStep,
};

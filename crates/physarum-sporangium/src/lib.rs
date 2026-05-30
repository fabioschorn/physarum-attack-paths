//! `physarum-sporangium` — Nuclei-inspired evidence enrichment for the physarum organism.
//!
//! ## Design mapping (Nuclei → physarum-sporangium)
//!
//! | Nuclei concept          | physarum-sporangium type     |
//! |-------------------------|------------------------------|
//! | Template / YAML rule    | `PatternTemplate`            |
//! | `info` block            | `TemplateInfo`               |
//! | Matcher (word/regex/...) | `PatternMatcher`            |
//! | Extractor               | `PatternExtractor`           |
//! | Severity                | `SeverityHint`               |
//! | ResultEvent             | `PatternFinding`             |
//! | Runner                  | `PatternRunner` + `RunPolicy`|
//!
//! ## Safety invariants (enforced, not trusted)
//!
//! - Templates not in `RunPolicy::allowed_check_ids` are rejected before network I/O.
//! - Response bodies are capped at `RunPolicy::max_response_bytes` (default 64 KiB).
//! - No subprocess, no external Nuclei binary, no arbitrary template loading from disk.
//! - Exploit-class checks are out of scope for this crate; this is detection only.
//!
//! ## Porting scope (first PR)
//!
//! Ported from Nuclei:
//! - Template schema (id, info, matchers, extractors, matchers-condition)
//! - Matcher types: `status`, `words`, `regex`
//! - Extractor types: `regex` (with group), `kval`, `json` (pointer)
//! - HTTP protocol handler (GET/POST/etc., path, headers, body)
//! - 6-level severity model (info/low/medium/high/critical/unknown)
//! - AND/OR matcher condition logic
//! - Allowlist-enforced runner with bounded response capture
//!
//! Planned (future PRs):
//! - DSL / XPath matchers and extractors
//! - Multi-step templates (chained requests)
//! - YAML template loading from disk (allowlisted directory)
//! - TCP/DNS protocol handlers
//! - PatternFinding → DiscoveryQuery bridge for physarum-llm (#106)

pub mod extractor;
pub mod finding;
pub mod matcher;
pub mod policy;
pub mod runner;
pub mod template;

// Flat re-exports for ergonomic use from physarum-maze / physarum-llm.
pub use extractor::{ExtractPart, ExtractedFact, ExtractorType, PatternExtractor};
pub use finding::{EvidenceSource, PatternFinding};
pub use matcher::{MatchCondition, MatchPart, MatcherType, PatternMatcher};
pub use policy::RunPolicy;
pub use runner::{evaluate_template, PatternRunner, ResponseData};
pub use template::{
    HttpCheck, HttpMethod, PatternProtocol, PatternTemplate, SeverityHint, TemplateInfo,
};

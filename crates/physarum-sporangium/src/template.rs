use crate::{extractor::PatternExtractor, matcher::MatchCondition, matcher::PatternMatcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vulnerability severity — mirrors Nuclei's 6-level model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityHint {
    Info,
    Low,
    Medium,
    High,
    Critical,
    #[default]
    Unknown,
}

/// Which network protocol the template probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternProtocol {
    Http,
    Tcp,
}

/// HTTP verb for an HttpCheck.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
}

/// Immutable metadata attached to every template (mirrors Nuclei `info` block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    pub authors: Vec<String>,
    pub description: Option<String>,
    pub severity: SeverityHint,
    pub tags: Vec<String>,
    pub references: Vec<String>,
}

/// A single HTTP probe definition — what to send and how to bound the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCheck {
    pub method: HttpMethod,
    /// Path to append to `http://<ip>:<port>`, e.g. `"/"`.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    /// Per-template response body cap (bytes). Overrides `RunPolicy::max_response_bytes`.
    pub max_response_bytes: Option<usize>,
}

impl HttpCheck {
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            path: path.into(),
            headers: HashMap::new(),
            body: None,
            max_response_bytes: None,
        }
    }
}

/// A compiled, validated pattern template. Immutable after construction.
///
/// Conceptual mapping to Nuclei:
/// - `id`               → template `id`
/// - `info`             → `info` block (name, authors, severity, tags)
/// - `http_check`       → `http[0]` request definition
/// - `matchers`         → `matchers` list
/// - `matchers_condition` → `matchers-condition` (And / Or)
/// - `extractors`       → `extractors` list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternTemplate {
    pub id: String,
    pub info: TemplateInfo,
    pub protocol: PatternProtocol,
    pub http_check: Option<HttpCheck>,
    pub matchers: Vec<PatternMatcher>,
    #[serde(default)]
    pub matchers_condition: MatchCondition,
    pub extractors: Vec<PatternExtractor>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

impl PatternTemplate {
    /// Validate the template structure. Returns an error if any regex in matchers
    /// or extractors fails to compile. Called at load time to fail fast.
    pub fn validate(&self) -> anyhow::Result<()> {
        for m in &self.matchers {
            m.validate()?;
        }
        for e in &self.extractors {
            e.validate()?;
        }
        Ok(())
    }
}

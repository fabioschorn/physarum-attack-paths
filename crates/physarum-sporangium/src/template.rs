//! Template schema — complete Nuclei template model ported to Rust.
//!
//! Covers all protocol types:
//! - HTTP (`http_check`) — existing
//! - TCP/Network (`tcp_request`) — raw byte exchange
//! - DNS (`dns_request`) — DNS record queries
//! - SSL/TLS (`ssl_request`) — certificate inspection
//! - WebSocket (`websocket_request`) — WS/WSS frame exchange

use crate::{extractor::PatternExtractor, matcher::MatchCondition, matcher::PatternMatcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Severity ─────────────────────────────────────────────────────────────────

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

// ── Protocol ─────────────────────────────────────────────────────────────────

/// Which network protocol the template probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternProtocol {
    Http,
    Tcp,
    Dns,
    Ssl,
    WebSocket,
}

// ── HTTP types ────────────────────────────────────────────────────────────────

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
    Patch,
}

/// A single HTTP probe definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCheck {
    pub method: HttpMethod,
    /// Path to append to `http://<ip>:<port>`, e.g. `"/"`.
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    /// Per-template response body cap (bytes). Overrides `RunPolicy::max_response_bytes`.
    pub max_response_bytes: Option<usize>,
    /// Redirect policy: 0 = no follow, positive = max redirects.
    #[serde(default = "default_redirects")]
    pub max_redirects: usize,
}

fn default_redirects() -> usize {
    10
}

impl HttpCheck {
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            path: path.into(),
            headers: HashMap::new(),
            body: None,
            max_response_bytes: None,
            max_redirects: 10,
        }
    }
}

// ── TCP / Network types ───────────────────────────────────────────────────────

/// Encoding for a TCP input payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputEncoding {
    #[default]
    Text,
    Hex,
}

/// A single send/receive step within a TCP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpInput {
    /// Data to send. May contain `{{variable}}` placeholders. Empty = banner grab only.
    #[serde(default)]
    pub data: String,
    /// Number of bytes to read after sending. 0 = no read for this step.
    #[serde(default)]
    pub read: usize,
    /// Variable name for data read in this step (for chaining into next inputs).
    pub name: Option<String>,
    #[serde(default)]
    pub encoding: InputEncoding,
}

/// TCP/Network protocol request definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpRequest {
    /// Send/receive sequence.
    pub inputs: Vec<TcpInput>,
    /// Max bytes to read in the final receive. Default 1024.
    #[serde(default = "default_read_size")]
    pub read_size: usize,
    /// If true, read until connection closes instead of `read_size`.
    #[serde(default)]
    pub read_all: bool,
    #[serde(default)]
    pub matchers: Vec<PatternMatcher>,
    #[serde(default)]
    pub matchers_condition: MatchCondition,
    #[serde(default)]
    pub extractors: Vec<PatternExtractor>,
}

fn default_read_size() -> usize {
    1024
}

// ── DNS types ─────────────────────────────────────────────────────────────────

/// DNS record type to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnsRecordType {
    #[default]
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    PTR,
    DS,
    ANY,
}

/// DNS protocol request definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRequest {
    /// Domain name to query. May contain `{{FQDN}}` and `{{Hostname}}`.
    pub name: String,
    #[serde(default, rename = "type")]
    pub record_type: DnsRecordType,
    /// Custom resolver addresses (host:port). Empty = use system default (8.8.8.8).
    #[serde(default)]
    pub resolvers: Vec<String>,
    /// Number of retries on failure.
    #[serde(default)]
    pub retries: u8,
    #[serde(default)]
    pub matchers: Vec<PatternMatcher>,
    #[serde(default)]
    pub matchers_condition: MatchCondition,
    #[serde(default)]
    pub extractors: Vec<PatternExtractor>,
}

// ── SSL types ─────────────────────────────────────────────────────────────────

/// TLS version constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

/// SSL/TLS inspection request definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SslRequest {
    /// Address override — if empty, the caller's `target_ip:port` is used.
    #[serde(default)]
    pub address: String,
    pub min_version: Option<TlsVersion>,
    pub max_version: Option<TlsVersion>,
    #[serde(default)]
    pub matchers: Vec<PatternMatcher>,
    #[serde(default)]
    pub matchers_condition: MatchCondition,
    #[serde(default)]
    pub extractors: Vec<PatternExtractor>,
}

// ── WebSocket types ───────────────────────────────────────────────────────────

/// A single send/receive step within a WebSocket request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsInput {
    /// Frame data to send. May contain `{{variable}}` placeholders.
    #[serde(default)]
    pub data: String,
    /// Maximum bytes (frame count × avg frame size) to read after sending.
    #[serde(default = "default_read_size")]
    pub read: usize,
    /// Variable name for received data (for chaining).
    pub name: Option<String>,
}

/// WebSocket protocol request definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketRequest {
    /// WebSocket URL. May contain `{{Hostname}}` and `{{Port}}`.
    pub address: String,
    #[serde(default)]
    pub inputs: Vec<WsInput>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub matchers: Vec<PatternMatcher>,
    #[serde(default)]
    pub matchers_condition: MatchCondition,
    #[serde(default)]
    pub extractors: Vec<PatternExtractor>,
}

// ── Template info ─────────────────────────────────────────────────────────────

/// Immutable metadata attached to every template (mirrors Nuclei `info` block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    #[serde(default)]
    pub authors: Vec<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub severity: SeverityHint,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    /// CVE identifier if this template targets a specific CVE.
    pub cve_id: Option<String>,
    /// CVSS score if known.
    pub cvss_score: Option<f32>,
    /// CWE identifiers.
    #[serde(default)]
    pub cwe_ids: Vec<String>,
}

// ── Full template ─────────────────────────────────────────────────────────────

/// A compiled, validated pattern template. Immutable after construction.
///
/// Exactly one protocol request field should be `Some(...)`. Multiple
/// protocol fields are supported for multi-protocol templates (run sequentially).
///
/// Conceptual mapping to Nuclei:
/// - `id`                  → template `id`
/// - `info`                → `info` block
/// - `http_check`          → `http[0]` request
/// - `tcp_request`         → `network[0]` request
/// - `dns_request`         → `dns[0]` request
/// - `ssl_request`         → `ssl[0]` request
/// - `websocket_request`   → `websocket[0]` request
/// - `matchers`            → global matchers (HTTP only for now)
/// - `extractors`          → global extractors (HTTP only for now)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default = "default_protocol")]
    pub protocol: PatternProtocol,

    // ── Per-protocol request definitions ────────────────────────────────────
    /// HTTP probe definition.
    pub http_check: Option<HttpCheck>,
    /// TCP/Network probe definition.
    pub tcp_request: Option<TcpRequest>,
    /// DNS query definition.
    pub dns_request: Option<DnsRequest>,
    /// SSL/TLS inspection definition.
    pub ssl_request: Option<SslRequest>,
    /// WebSocket exchange definition.
    pub websocket_request: Option<WebSocketRequest>,

    // ── Global matchers and extractors (HTTP) ────────────────────────────────
    #[serde(default)]
    pub matchers: Vec<PatternMatcher>,
    #[serde(default)]
    pub matchers_condition: MatchCondition,
    #[serde(default)]
    pub extractors: Vec<PatternExtractor>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

fn default_protocol() -> PatternProtocol {
    PatternProtocol::Http
}

impl PatternTemplate {
    /// Validate the template structure — compile all regex patterns.
    pub fn validate(&self) -> anyhow::Result<()> {
        for m in &self.matchers {
            m.validate()?;
        }
        for e in &self.extractors {
            e.validate()?;
        }
        // Validate TCP request matchers/extractors
        if let Some(tcp) = &self.tcp_request {
            for m in &tcp.matchers {
                m.validate()?;
            }
            for e in &tcp.extractors {
                e.validate()?;
            }
        }
        // Validate DNS request matchers/extractors
        if let Some(dns) = &self.dns_request {
            for m in &dns.matchers {
                m.validate()?;
            }
            for e in &dns.extractors {
                e.validate()?;
            }
        }
        // Validate SSL request matchers/extractors
        if let Some(ssl) = &self.ssl_request {
            for m in &ssl.matchers {
                m.validate()?;
            }
            for e in &ssl.extractors {
                e.validate()?;
            }
        }
        // Validate WebSocket request matchers/extractors
        if let Some(ws) = &self.websocket_request {
            for m in &ws.matchers {
                m.validate()?;
            }
            for e in &ws.extractors {
                e.validate()?;
            }
        }
        Ok(())
    }

    /// Collect all matchers for the primary protocol.
    pub fn effective_matchers(&self) -> &[PatternMatcher] {
        match self.protocol {
            PatternProtocol::Http => &self.matchers,
            PatternProtocol::Tcp => self
                .tcp_request
                .as_ref()
                .map(|r| r.matchers.as_slice())
                .unwrap_or(&[]),
            PatternProtocol::Dns => self
                .dns_request
                .as_ref()
                .map(|r| r.matchers.as_slice())
                .unwrap_or(&[]),
            PatternProtocol::Ssl => self
                .ssl_request
                .as_ref()
                .map(|r| r.matchers.as_slice())
                .unwrap_or(&[]),
            PatternProtocol::WebSocket => self
                .websocket_request
                .as_ref()
                .map(|r| r.matchers.as_slice())
                .unwrap_or(&[]),
        }
    }

    /// Collect all extractors for the primary protocol.
    pub fn effective_extractors(&self) -> &[PatternExtractor] {
        match self.protocol {
            PatternProtocol::Http => &self.extractors,
            PatternProtocol::Tcp => self
                .tcp_request
                .as_ref()
                .map(|r| r.extractors.as_slice())
                .unwrap_or(&[]),
            PatternProtocol::Dns => self
                .dns_request
                .as_ref()
                .map(|r| r.extractors.as_slice())
                .unwrap_or(&[]),
            PatternProtocol::Ssl => self
                .ssl_request
                .as_ref()
                .map(|r| r.extractors.as_slice())
                .unwrap_or(&[]),
            PatternProtocol::WebSocket => self
                .websocket_request
                .as_ref()
                .map(|r| r.extractors.as_slice())
                .unwrap_or(&[]),
        }
    }

    /// Effective matchers condition for the primary protocol.
    pub fn effective_matchers_condition(&self) -> MatchCondition {
        match self.protocol {
            PatternProtocol::Http => self.matchers_condition,
            PatternProtocol::Tcp => self
                .tcp_request
                .as_ref()
                .map(|r| r.matchers_condition)
                .unwrap_or_default(),
            PatternProtocol::Dns => self
                .dns_request
                .as_ref()
                .map(|r| r.matchers_condition)
                .unwrap_or_default(),
            PatternProtocol::Ssl => self
                .ssl_request
                .as_ref()
                .map(|r| r.matchers_condition)
                .unwrap_or_default(),
            PatternProtocol::WebSocket => self
                .websocket_request
                .as_ref()
                .map(|r| r.matchers_condition)
                .unwrap_or_default(),
        }
    }
}

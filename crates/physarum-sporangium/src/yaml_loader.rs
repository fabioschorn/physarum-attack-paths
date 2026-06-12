//! Nuclei-compatible YAML template loader.
//!
//! Reads templates from `templates/nuclei-legacy/` (or any configured directory)
//! and converts them to [`PatternTemplate`] structs executable by physarum-sporangium.
//!
//! # Filter model
//!
//! Templates are filtered at load time via [`TemplateFilter`]:
//! - `tags`     — include templates whose tag list intersects (OR logic)
//! - `severity` — include templates with any of these severity levels
//! - `ids`      — include specific template IDs (bypasses other filters)
//!
//! # Environment variables
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `PHYSARUM_TEMPLATE_DIR` | `templates/nuclei-legacy` | Directory to scan |
//! | `PHYSARUM_TEMPLATE_TAGS` | *(empty = all)* | Comma-separated tag filter |
//! | `PHYSARUM_TEMPLATE_SEVERITY` | *(empty = all)* | Comma-separated severity filter |
//! | `PHYSARUM_TEMPLATE_IDS` | *(empty = all)* | Comma-separated template ID filter |

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

// ── Embedded template archive ─────────────────────────────────────────────────

static TEMPLATES_TAR_ZST: &[u8] = include_bytes!("../data/nuclei-templates.tar.zst");
static EXTRACTED_DIR: OnceLock<PathBuf> = OnceLock::new();

fn extract_embedded_templates() -> PathBuf {
    let dest = PathBuf::from("/tmp/physarum/templates");
    let result_dir = dest.join("nuclei-legacy");
    let sentinel = result_dir.join(".embedded-extracted");

    if sentinel.exists() {
        return result_dir;
    }

    std::fs::create_dir_all(&dest).expect("cannot create /tmp/physarum/templates");

    info!("extracting embedded nuclei templates to {}", dest.display());
    let decoder = zstd::stream::Decoder::new(std::io::Cursor::new(TEMPLATES_TAR_ZST))
        .expect("zstd decoder init");
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(&dest).expect("tar unpack failed");

    std::fs::write(&sentinel, "").ok();
    info!("templates extracted entries={}", walkdir::WalkDir::new(&result_dir).into_iter().count());

    result_dir
}

use crate::extractor::{ExtractPart, ExtractorType, PatternExtractor};
use crate::matcher::{MatchCondition, MatchPart, MatcherType, PatternMatcher};
use crate::template::{
    DnsRecordType, DnsRequest, HttpCheck, HttpMethod, PatternProtocol, PatternTemplate,
    SeverityHint, SslRequest, TcpInput, TcpRequest, TemplateInfo,
};

// ── Filter ────────────────────────────────────────────────────────────────────

/// Runtime filter applied during template loading.
#[derive(Debug, Default, Clone)]
pub struct TemplateFilter {
    /// Include templates whose tags intersect with this list (OR). Empty = all.
    pub tags: Vec<String>,
    /// Include templates with any of these severity levels. Empty = all.
    pub severity: Vec<String>,
    /// Include these specific template IDs regardless of other filters.
    pub ids: Vec<String>,
}

impl TemplateFilter {
    /// Build a filter from environment variables.
    pub fn from_env() -> Self {
        Self {
            tags: env_list("PHYSARUM_TEMPLATE_TAGS"),
            severity: env_list("PHYSARUM_TEMPLATE_SEVERITY"),
            ids: env_list("PHYSARUM_TEMPLATE_IDS"),
        }
    }

    fn matches(&self, tmpl: &NucleiTemplate) -> bool {
        // ID pinning bypasses all other filters
        if !self.ids.is_empty() {
            return self.ids.iter().any(|id| id.eq_ignore_ascii_case(&tmpl.id));
        }
        // Severity filter
        if !self.severity.is_empty() {
            let sev = tmpl.info.severity.as_str();
            if !self.severity.iter().any(|s| s.eq_ignore_ascii_case(sev)) {
                return false;
            }
        }
        // Tag filter
        if !self.tags.is_empty() {
            let has_match = self
                .tags
                .iter()
                .any(|ft| tmpl.info.tags.iter().any(|t| t.eq_ignore_ascii_case(ft)));
            if !has_match {
                return false;
            }
        }
        true
    }
}

fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

// ── Public loader ─────────────────────────────────────────────────────────────

/// Resolve the template directory.
///
/// Priority:
/// 1. `PHYSARUM_TEMPLATE_DIR` env var (explicit override — Docker, tests, CI)
/// 2. Embedded `nuclei-templates.tar.zst` extracted to `/tmp/physarum/templates/nuclei-legacy/`
pub fn template_dir() -> PathBuf {
    if let Ok(v) = std::env::var("PHYSARUM_TEMPLATE_DIR") {
        return PathBuf::from(v);
    }
    EXTRACTED_DIR.get_or_init(extract_embedded_templates).clone()
}

/// Load all templates from `dir` that pass `filter`, converting from Nuclei
/// YAML format to [`PatternTemplate`]. Unreadable or unparseable files are
/// skipped with a warning.
pub fn load_nuclei_templates(dir: &Path, filter: &TemplateFilter) -> Vec<PatternTemplate> {
    if !dir.exists() {
        warn!(path = %dir.display(), "template directory not found — skipping YAML loader");
        return vec![];
    }

    let mut templates = Vec::new();
    let mut skipped = 0usize;

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            matches!(
                e.path().extension().and_then(|x| x.to_str()),
                Some("yaml") | Some("yml")
            )
        })
    {
        let path = entry.path();
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                debug!(path = %path.display(), error = %e, "skipping unreadable template");
                skipped += 1;
                continue;
            }
        };

        let nuclei: NucleiTemplate = match serde_yaml::from_str(&content) {
            Ok(t) => t,
            Err(e) => {
                debug!(path = %path.display(), error = %e, "skipping unparseable template");
                skipped += 1;
                continue;
            }
        };

        if !filter.matches(&nuclei) {
            continue;
        }

        match nuclei.into_pattern_template() {
            Some(pt) => templates.push(pt),
            None => {
                skipped += 1;
            }
        }
    }

    tracing::info!(
        dir = %dir.display(),
        loaded = templates.len(),
        skipped,
        "nuclei YAML templates loaded"
    );

    templates
}

// ── Nuclei YAML structs ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NucleiTemplate {
    pub id: String,
    pub info: NucleiInfo,
    #[serde(default)]
    pub http: Vec<NucleiHttpRequest>,
    #[serde(default)]
    pub dns: Vec<NucleiDnsRequest>,
    #[serde(default)]
    pub ssl: Vec<NucleiSslRequest>,
    #[serde(default)]
    pub network: Vec<NucleiNetworkRequest>,
    #[serde(default)]
    pub tcp: Vec<NucleiNetworkRequest>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    pub name: String,
    #[serde(default)]
    pub author: StringOrList,
    #[serde(default)]
    pub severity: NucleiSeverity,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(rename = "cve-id", default)]
    pub cve_id: Option<String>,
    #[serde(rename = "cvss-score", default)]
    pub cvss_score: Option<f32>,
    #[serde(rename = "cwe-id", default)]
    pub cwe_id: Option<StringOrList>,
    #[serde(default, deserialize_with = "deser_tags")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub reference: StringOrList,
}

#[derive(Debug, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum NucleiSeverity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl NucleiSeverity {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }

    fn to_severity_hint(&self) -> SeverityHint {
        match self {
            Self::Info | Self::Unknown => SeverityHint::Info,
            Self::Low => SeverityHint::Low,
            Self::Medium => SeverityHint::Medium,
            Self::High => SeverityHint::High,
            Self::Critical => SeverityHint::Critical,
        }
    }
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NucleiHttpRequest {
    #[serde(default)]
    pub method: NucleiHttpMethod,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub matchers: Vec<NucleiMatcher>,
    #[serde(rename = "matchers-condition", default)]
    pub matchers_condition: NucleiCondition,
    #[serde(default)]
    pub extractors: Vec<NucleiExtractor>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
enum NucleiHttpMethod {
    #[default]
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
}

// ── DNS ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NucleiDnsRequest {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub record_type: NucleiDnsType,
    #[serde(default)]
    pub matchers: Vec<NucleiMatcher>,
    #[serde(rename = "matchers-condition", default)]
    pub matchers_condition: NucleiCondition,
    #[serde(default)]
    pub extractors: Vec<NucleiExtractor>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
enum NucleiDnsType {
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
    AXFR,
    ANY,
}

// ── SSL ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NucleiSslRequest {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub matchers: Vec<NucleiMatcher>,
    #[serde(rename = "matchers-condition", default)]
    pub matchers_condition: NucleiCondition,
    #[serde(default)]
    pub extractors: Vec<NucleiExtractor>,
}

// ── Network / TCP ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NucleiNetworkRequest {
    #[serde(default)]
    pub inputs: Vec<NucleiNetworkInput>,
    #[allow(dead_code)]
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(rename = "read-size", default = "default_read_size")]
    pub read_size: usize,
    #[serde(default)]
    pub matchers: Vec<NucleiMatcher>,
    #[serde(rename = "matchers-condition", default)]
    pub matchers_condition: NucleiCondition,
    #[serde(default)]
    pub extractors: Vec<NucleiExtractor>,
}

fn default_read_size() -> usize {
    1024
}

#[derive(Debug, Deserialize)]
struct NucleiNetworkInput {
    #[serde(default)]
    pub data: String,
    #[serde(default = "default_read_size")]
    pub read: usize,
}

// ── Matchers ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NucleiMatcher {
    #[serde(rename = "type")]
    pub matcher_type: NucleiMatcherType,
    #[serde(default)]
    pub part: NucleiPart,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub dsl: Vec<String>,
    #[serde(default)]
    pub binary: Vec<String>,
    #[serde(default)]
    pub size: Vec<usize>,
    #[serde(default)]
    pub condition: NucleiCondition,
    #[serde(rename = "case-insensitive", default)]
    pub case_insensitive: bool,
    #[serde(default)]
    pub negative: bool,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NucleiMatcherType {
    Word,
    Regex,
    Status,
    Dsl,
    Binary,
    Size,
    Xpath,
}

// ── Extractors ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NucleiExtractor {
    #[serde(rename = "type")]
    pub extractor_type: NucleiExtractorType,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub part: NucleiPart,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub group: usize,
    #[serde(default)]
    pub kval: Vec<String>,
    #[serde(default)]
    pub json: Vec<String>,
    #[serde(default)]
    pub xpath: Vec<String>,
    #[serde(default)]
    pub dsl: Vec<String>,
    #[serde(default)]
    pub attribute: Option<String>,
    #[serde(default)]
    pub internal: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NucleiExtractorType {
    Regex,
    Kval,
    Json,
    Xpath,
    Dsl,
}

// ── Shared enums ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum NucleiCondition {
    #[default]
    And,
    Or,
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum NucleiPart {
    #[default]
    Body,
    Header,
    All,
    Raw,
}

// ── Serde helpers ─────────────────────────────────────────────────────────────

/// Nuclei tags can be `"nginx,cve,http"` (string) or `["nginx","cve"]` (list).
fn deser_tags<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = StringOrList::deserialize(deserializer)?;
    Ok(s.into_vec()
        .into_iter()
        .flat_map(|s| {
            s.split(',')
                .map(|t| t.trim().to_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect())
}

#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum StringOrList {
    #[default]
    None,
    Single(String),
    List(Vec<String>),
}

impl StringOrList {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::None => vec![],
            Self::Single(s) => vec![s],
            Self::List(v) => v,
        }
    }
}

// ── Conversion: NucleiTemplate → PatternTemplate ──────────────────────────────

impl NucleiTemplate {
    fn into_pattern_template(self) -> Option<PatternTemplate> {
        let info = TemplateInfo {
            name: self.info.name.clone(),
            authors: self.info.author.into_vec(),
            description: self.info.description,
            remediation: self.info.remediation,
            severity: self.info.severity.to_severity_hint(),
            tags: self.info.tags,
            references: self.info.reference.into_vec(),
            cve_id: self.info.cve_id,
            cvss_score: self.info.cvss_score,
            cwe_ids: self.info.cwe_id.map(|c| c.into_vec()).unwrap_or_default(),
        };

        // Pick the first supported protocol block
        if let Some(http) = self.http.into_iter().next() {
            return Some(http_template(self.id, info, http));
        }
        if let Some(dns) = self.dns.into_iter().next() {
            return Some(dns_template(self.id, info, dns));
        }
        if let Some(ssl) = self.ssl.into_iter().next() {
            return Some(ssl_template(self.id, info, ssl));
        }
        // network: and tcp: are both raw TCP
        let net = self
            .network
            .into_iter()
            .next()
            .or_else(|| self.tcp.into_iter().next());
        if let Some(net) = net {
            return Some(network_template(self.id, info, net));
        }

        None
    }
}

// ── Protocol converters ───────────────────────────────────────────────────────

fn http_template(id: String, info: TemplateInfo, req: NucleiHttpRequest) -> PatternTemplate {
    let path = req.path.into_iter().next().unwrap_or_else(|| "/".into());
    // Strip Nuclei's {{BaseURL}} prefix if present
    let path = path
        .trim_start_matches("{{BaseURL}}")
        .trim_start_matches("{{RootURL}}")
        .to_string();
    let path = if path.is_empty() { "/".into() } else { path };

    let method = match req.method {
        NucleiHttpMethod::POST => HttpMethod::Post,
        NucleiHttpMethod::PUT => HttpMethod::Put,
        NucleiHttpMethod::PATCH => HttpMethod::Patch,
        NucleiHttpMethod::DELETE => HttpMethod::Get, // map unsupported → GET
        NucleiHttpMethod::HEAD => HttpMethod::Get,
        NucleiHttpMethod::OPTIONS => HttpMethod::Get,
        _ => HttpMethod::Get,
    };

    let matchers = req
        .matchers
        .into_iter()
        .filter_map(convert_matcher)
        .collect();
    let extractors = req
        .extractors
        .into_iter()
        .filter_map(convert_extractor)
        .collect();

    PatternTemplate {
        id,
        info,
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck {
            method,
            path,
            headers: req.headers,
            body: req.body,
            max_response_bytes: None,
            max_redirects: 3,
        }),
        tcp_request: None,
        dns_request: None,
        ssl_request: None,
        websocket_request: None,
        matchers,
        matchers_condition: convert_condition(req.matchers_condition),
        extractors,
        stop_at_first_match: false,
    }
}

fn dns_template(id: String, info: TemplateInfo, req: NucleiDnsRequest) -> PatternTemplate {
    let record_type = match req.record_type {
        NucleiDnsType::A => DnsRecordType::A,
        NucleiDnsType::AAAA => DnsRecordType::AAAA,
        NucleiDnsType::CNAME => DnsRecordType::CNAME,
        NucleiDnsType::MX => DnsRecordType::MX,
        NucleiDnsType::TXT => DnsRecordType::TXT,
        NucleiDnsType::NS => DnsRecordType::NS,
        NucleiDnsType::SOA => DnsRecordType::SOA,
        NucleiDnsType::PTR => DnsRecordType::PTR,
        NucleiDnsType::DS => DnsRecordType::DS,
        NucleiDnsType::AXFR | NucleiDnsType::ANY => DnsRecordType::ANY,
    };

    let matchers = req
        .matchers
        .into_iter()
        .filter_map(convert_matcher)
        .collect();
    let extractors = req
        .extractors
        .into_iter()
        .filter_map(convert_extractor)
        .collect();

    PatternTemplate {
        id,
        info,
        protocol: PatternProtocol::Dns,
        http_check: None,
        tcp_request: None,
        dns_request: Some(DnsRequest {
            name: req.name,
            record_type,
            resolvers: vec![],
            retries: 2,
            matchers,
            matchers_condition: convert_condition(req.matchers_condition),
            extractors,
        }),
        ssl_request: None,
        websocket_request: None,
        matchers: vec![],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

fn ssl_template(id: String, info: TemplateInfo, req: NucleiSslRequest) -> PatternTemplate {
    let matchers = req
        .matchers
        .into_iter()
        .filter_map(convert_matcher)
        .collect();
    let extractors = req
        .extractors
        .into_iter()
        .filter_map(convert_extractor)
        .collect();

    PatternTemplate {
        id,
        info,
        protocol: PatternProtocol::Ssl,
        http_check: None,
        tcp_request: None,
        dns_request: None,
        ssl_request: Some(SslRequest {
            address: req.address,
            min_version: None,
            max_version: None,
            matchers,
            matchers_condition: convert_condition(req.matchers_condition),
            extractors,
        }),
        websocket_request: None,
        matchers: vec![],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

fn network_template(id: String, info: TemplateInfo, req: NucleiNetworkRequest) -> PatternTemplate {
    let inputs = req
        .inputs
        .into_iter()
        .map(|i| TcpInput {
            data: i.data,
            read: i.read,
            name: None,
            encoding: crate::template::InputEncoding::Text,
        })
        .collect();

    let matchers = req
        .matchers
        .into_iter()
        .filter_map(convert_matcher)
        .collect();
    let extractors = req
        .extractors
        .into_iter()
        .filter_map(convert_extractor)
        .collect();

    PatternTemplate {
        id,
        info,
        protocol: PatternProtocol::Tcp,
        http_check: None,
        tcp_request: Some(TcpRequest {
            inputs,
            read_size: req.read_size,
            read_all: false,
            matchers,
            matchers_condition: convert_condition(req.matchers_condition),
            extractors,
        }),
        dns_request: None,
        ssl_request: None,
        websocket_request: None,
        matchers: vec![],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

// ── Matcher / extractor conversion ────────────────────────────────────────────

fn convert_matcher(m: NucleiMatcher) -> Option<PatternMatcher> {
    let part = match m.part {
        NucleiPart::Header => MatchPart::Headers,
        NucleiPart::All | NucleiPart::Raw => MatchPart::All,
        NucleiPart::Body => MatchPart::Body,
    };

    let matcher_type = match m.matcher_type {
        NucleiMatcherType::Word => MatcherType::Words {
            words: m.words,
            all_must_match: matches!(m.condition, NucleiCondition::And),
            case_insensitive: m.case_insensitive,
        },
        NucleiMatcherType::Regex => MatcherType::Regex { patterns: m.regex },
        NucleiMatcherType::Status => MatcherType::Status { codes: m.status },
        NucleiMatcherType::Dsl => MatcherType::Dsl {
            expressions: m.dsl,
            all_must_match: matches!(m.condition, NucleiCondition::And),
        },
        NucleiMatcherType::Binary => MatcherType::Binary {
            patterns: m.binary,
            case_insensitive: false,
        },
        NucleiMatcherType::Size => MatcherType::Size { sizes: m.size },
        NucleiMatcherType::Xpath => MatcherType::XPath {
            queries: m.words,
            all_must_match: matches!(m.condition, NucleiCondition::And),
        },
    };

    Some(PatternMatcher {
        name: m.name.unwrap_or_default(),
        matcher_type,
        part,
        negate: m.negative,
    })
}

fn convert_extractor(e: NucleiExtractor) -> Option<PatternExtractor> {
    let part = match e.part {
        NucleiPart::Header => ExtractPart::Headers,
        _ => ExtractPart::Body,
    };

    let extractor_type = match e.extractor_type {
        NucleiExtractorType::Regex => ExtractorType::Regex {
            pattern: e.regex.into_iter().next()?,
            group: e.group,
        },
        NucleiExtractorType::Kval => ExtractorType::Kval {
            key: e.kval.into_iter().next().unwrap_or_default(),
        },
        NucleiExtractorType::Json => ExtractorType::Json {
            pointer: e.json.into_iter().next()?,
        },
        NucleiExtractorType::Xpath => ExtractorType::XPath {
            query: e.xpath.into_iter().next()?,
            attribute: e.attribute,
        },
        NucleiExtractorType::Dsl => ExtractorType::Dsl {
            expression: e.dsl.into_iter().next()?,
        },
    };

    Some(PatternExtractor {
        name: e.name.unwrap_or_default(),
        extractor_type,
        part,
        internal: e.internal,
    })
}

fn convert_condition(c: NucleiCondition) -> MatchCondition {
    match c {
        NucleiCondition::And => MatchCondition::And,
        NucleiCondition::Or => MatchCondition::Or,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NGINX_DETECT: &str = r#"
id: nginx-detect
info:
  name: Nginx Server Detection
  author: projectdiscovery
  severity: info
  tags: tech,nginx,detect
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "nginx"
        case-insensitive: true
      - type: status
        status:
          - 200
          - 301
    extractors:
      - type: regex
        name: version
        part: header
        group: 1
        regex:
          - "Server: nginx/([0-9]+\\.[0-9]+\\.[0-9]+)"
"#;

    const CVE_TEMPLATE: &str = r#"
id: CVE-2021-23017
info:
  name: nginx Resolver Off-by-One
  author: projectdiscovery
  severity: high
  cve-id: CVE-2021-23017
  cvss-score: 7.7
  tags: cve,cve2021,nginx
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "Server: nginx/1\\.18\\."
"#;

    const DSL_TEMPLATE: &str = r#"
id: ssl-expired
info:
  name: Expired SSL Certificate
  author: pdteam
  severity: high
  tags: ssl,expired
ssl:
  - address: "{{Host}}:{{Port}}"
    matchers:
      - type: dsl
        dsl:
          - "expired == true"
"#;

    #[test]
    fn parse_nginx_detect() {
        let t: NucleiTemplate = serde_yaml::from_str(NGINX_DETECT).unwrap();
        assert_eq!(t.id, "nginx-detect");
        assert!(t.info.tags.contains(&"nginx".to_string()));
        assert_eq!(t.http.len(), 1);
        let http = &t.http[0];
        assert_eq!(http.matchers.len(), 2);
        assert_eq!(http.extractors.len(), 1);
    }

    #[test]
    fn convert_nginx_to_pattern_template() {
        let t: NucleiTemplate = serde_yaml::from_str(NGINX_DETECT).unwrap();
        let pt = t.into_pattern_template().unwrap();
        assert_eq!(pt.id, "nginx-detect");
        assert_eq!(pt.protocol, PatternProtocol::Http);
        assert!(pt.http_check.is_some());
        assert_eq!(pt.http_check.unwrap().path, "/");
    }

    #[test]
    fn parse_cve_template_metadata() {
        let t: NucleiTemplate = serde_yaml::from_str(CVE_TEMPLATE).unwrap();
        assert_eq!(t.info.cve_id.as_deref(), Some("CVE-2021-23017"));
        assert_eq!(t.info.cvss_score, Some(7.7));
        assert_eq!(t.info.severity, NucleiSeverity::High);
        let pt = t.into_pattern_template().unwrap();
        assert_eq!(pt.info.cve_id.as_deref(), Some("CVE-2021-23017"));
        assert_eq!(pt.info.cvss_score, Some(7.7));
    }

    #[test]
    fn parse_ssl_dsl_template() {
        let t: NucleiTemplate = serde_yaml::from_str(DSL_TEMPLATE).unwrap();
        let pt = t.into_pattern_template().unwrap();
        assert_eq!(pt.protocol, PatternProtocol::Ssl);
        assert!(pt.ssl_request.is_some());
    }

    #[test]
    fn filter_by_tag() {
        let filter = TemplateFilter {
            tags: vec!["nginx".into()],
            severity: vec![],
            ids: vec![],
        };
        let t: NucleiTemplate = serde_yaml::from_str(NGINX_DETECT).unwrap();
        assert!(filter.matches(&t));

        let t2: NucleiTemplate = serde_yaml::from_str(DSL_TEMPLATE).unwrap();
        assert!(!filter.matches(&t2));
    }

    #[test]
    fn filter_by_severity() {
        let filter = TemplateFilter {
            tags: vec![],
            severity: vec!["high".into()],
            ids: vec![],
        };
        let t: NucleiTemplate = serde_yaml::from_str(CVE_TEMPLATE).unwrap();
        assert!(filter.matches(&t));

        let t2: NucleiTemplate = serde_yaml::from_str(NGINX_DETECT).unwrap();
        assert!(!filter.matches(&t2)); // severity info
    }

    #[test]
    fn filter_by_id_bypasses_tag() {
        let filter = TemplateFilter {
            tags: vec!["ssl".into()],
            severity: vec![],
            ids: vec!["nginx-detect".into()],
        };
        let t: NucleiTemplate = serde_yaml::from_str(NGINX_DETECT).unwrap();
        assert!(filter.matches(&t)); // ID match bypasses tag mismatch
    }
}

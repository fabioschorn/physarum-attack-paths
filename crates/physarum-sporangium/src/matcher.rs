//! Pattern matchers — ported from Nuclei `pkg/operators/matchers`.
//!
//! Ported matcher types:
//! - `status`  → [`MatcherType::Status`]
//! - `word`    → [`MatcherType::Words`]
//! - `regex`   → [`MatcherType::Regex`]
//! - `binary`  → [`MatcherType::Binary`]  (hex-encoded byte patterns)
//! - `size`    → [`MatcherType::Size`]    (response body length)
//! - `dsl`     → [`MatcherType::Dsl`]    (evalexpr boolean expressions)
//! - `xpath`   → [`MatcherType::XPath`]  (XPath 1.0 on HTML/XML)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::runner::ResponseData;

// ── Condition ─────────────────────────────────────────────────────────────────

/// Whether all matchers must pass (AND) or any one suffices (OR).
/// Nuclei default is OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    And,
    #[default]
    Or,
}

// ── Part ──────────────────────────────────────────────────────────────────────

/// Which part of the response to test against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchPart {
    /// HTTP numeric status code as a string.
    Status,
    /// Response body (capped at RunPolicy::max_response_bytes).
    #[default]
    Body,
    /// All response headers joined as "key: value\n..." lines.
    Headers,
    /// Status line + headers + body concatenated.
    Raw,
    /// Raw bytes for TCP/binary response data.
    Data,
    /// DNS answer section text.
    DnsAnswer,
    /// DNS NS section text.
    DnsNs,
    /// DNS extra section text.
    DnsExtra,
    /// SSL certificate PEM or text representation.
    SslCert,
    /// WebSocket response frames concatenated.
    WsResponse,
    /// Full transaction (request + response).
    All,
}

// ── Matcher types ─────────────────────────────────────────────────────────────

/// What the matcher tests for — complete Nuclei matcher type set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MatcherType {
    /// Match HTTP response status codes.
    Status { codes: Vec<u16> },
    /// Match fixed strings in the response.
    Words {
        words: Vec<String>,
        #[serde(default)]
        case_insensitive: bool,
        /// If true, all words must appear.
        #[serde(default)]
        all_must_match: bool,
    },
    /// Match Rust regular expressions against the response.
    Regex { patterns: Vec<String> },
    /// Match hex-encoded binary byte patterns against the raw response bytes.
    ///
    /// Example: `patterns: ["48656c6c6f"]` matches the bytes for "Hello".
    Binary {
        patterns: Vec<String>,
        #[serde(default)]
        case_insensitive: bool,
    },
    /// Match response body length against expected sizes (in bytes).
    Size { sizes: Vec<usize> },
    /// Evaluate `evalexpr` boolean expressions against a DSL context map
    /// built from the response (status_code, body, all_headers, header_*, extra fields).
    Dsl {
        expressions: Vec<String>,
        #[serde(default)]
        all_must_match: bool,
    },
    /// Execute XPath 1.0 queries against the HTML or XML response body.
    /// Returns true when the query selects at least one node.
    XPath {
        queries: Vec<String>,
        #[serde(default)]
        all_must_match: bool,
    },
}

// ── PatternMatcher ────────────────────────────────────────────────────────────

/// A single matcher within a template. Immutable after load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatcher {
    /// Human-readable identifier shown in matched_condition_summary.
    pub name: String,
    pub matcher_type: MatcherType,
    #[serde(default)]
    pub part: MatchPart,
    /// Invert the match result (logical NOT).
    #[serde(default)]
    pub negate: bool,
}

impl PatternMatcher {
    /// Pre-validate at load time: compile all regex patterns.
    pub fn validate(&self) -> anyhow::Result<()> {
        match &self.matcher_type {
            MatcherType::Regex { patterns } => {
                for p in patterns {
                    regex::Regex::new(p).map_err(|e| {
                        anyhow::anyhow!("matcher '{}': invalid regex {:?}: {}", self.name, p, e)
                    })?;
                }
            }
            MatcherType::Binary { patterns, .. } => {
                for p in patterns {
                    hex::decode(p).map_err(|e| {
                        anyhow::anyhow!(
                            "matcher '{}': invalid hex pattern {:?}: {}",
                            self.name,
                            p,
                            e
                        )
                    })?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Apply this matcher to `resp`. Returns `(matched, snippet)`.
    pub fn apply(&self, resp: &ResponseData) -> (bool, String) {
        let (raw_matched, snippet) = self.apply_inner(resp);
        let matched = if self.negate {
            !raw_matched
        } else {
            raw_matched
        };
        (matched, snippet)
    }

    /// Apply this matcher to a pre-built DSL context (avoids re-building it for DSL matchers).
    pub fn apply_with_dsl_ctx(
        &self,
        resp: &ResponseData,
        dsl_ctx: &HashMap<String, String>,
    ) -> (bool, String) {
        if let MatcherType::Dsl {
            expressions,
            all_must_match,
        } = &self.matcher_type
        {
            let result = apply_dsl(expressions, *all_must_match, dsl_ctx);
            let matched = if self.negate { !result.0 } else { result.0 };
            return (matched, result.1);
        }
        self.apply(resp)
    }

    fn apply_inner(&self, resp: &ResponseData) -> (bool, String) {
        match &self.matcher_type {
            MatcherType::Status { codes } => {
                let matched = codes.contains(&resp.status);
                (matched, format!("status={}", resp.status))
            }

            MatcherType::Words {
                words,
                case_insensitive,
                all_must_match,
            } => {
                let haystack = response_part_text(resp, &self.part);
                let haystack_cmp = if *case_insensitive {
                    haystack.to_lowercase()
                } else {
                    haystack.clone()
                };

                let matched_words: Vec<&str> = words
                    .iter()
                    .filter(|w| {
                        let needle = if *case_insensitive {
                            w.to_lowercase()
                        } else {
                            w.to_string()
                        };
                        haystack_cmp.contains(&needle)
                    })
                    .map(String::as_str)
                    .collect();

                let overall = if *all_must_match {
                    matched_words.len() == words.len()
                } else {
                    !matched_words.is_empty()
                };

                let snippet = if overall {
                    format!("words={matched_words:?}")
                } else {
                    String::new()
                };
                (overall, snippet)
            }

            MatcherType::Regex { patterns } => {
                let text = response_part_text(resp, &self.part);
                for pattern in patterns {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        if let Some(m) = re.find(&text) {
                            return (true, format!("regex={:?}", m.as_str()));
                        }
                    }
                }
                (false, String::new())
            }

            MatcherType::Binary {
                patterns,
                case_insensitive,
            } => {
                let raw: Vec<u8> = match &self.part {
                    MatchPart::Data => resp.raw_bytes.clone().unwrap_or_default(),
                    _ => resp
                        .raw_bytes
                        .clone()
                        .unwrap_or_else(|| resp.body.as_bytes().to_vec()),
                };

                for hex_pat in patterns {
                    if let Ok(pat_bytes) = hex::decode(hex_pat) {
                        if pat_bytes.is_empty() {
                            continue;
                        }
                        let found = if *case_insensitive {
                            let raw_lower: Vec<u8> =
                                raw.iter().map(|b| b.to_ascii_lowercase()).collect();
                            let pat_lower: Vec<u8> =
                                pat_bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
                            raw_lower
                                .windows(pat_lower.len())
                                .any(|w| w == pat_lower.as_slice())
                        } else {
                            raw.windows(pat_bytes.len())
                                .any(|w| w == pat_bytes.as_slice())
                        };
                        if found {
                            return (true, format!("binary={hex_pat}"));
                        }
                    }
                }
                (false, String::new())
            }

            MatcherType::Size { sizes } => {
                let body_len = resp.body.len();
                for &expected in sizes {
                    if body_len == expected {
                        return (true, format!("size={expected}"));
                    }
                }
                (false, String::new())
            }

            MatcherType::Dsl {
                expressions,
                all_must_match,
            } => {
                let dsl_ctx = crate::dsl::build_dsl_context_from_response(resp);
                apply_dsl(expressions, *all_must_match, &dsl_ctx)
            }

            MatcherType::XPath {
                queries,
                all_must_match,
            } => {
                let text = response_part_text(resp, &self.part);
                apply_xpath(queries, *all_must_match, &text)
            }
        }
    }
}

// ── DSL evaluation ────────────────────────────────────────────────────────────

fn apply_dsl(
    expressions: &[String],
    all_must_match: bool,
    ctx: &HashMap<String, String>,
) -> (bool, String) {
    let mut matched = Vec::new();
    for expr in expressions {
        match crate::dsl::evaluate_dsl(expr, ctx) {
            Ok(true) => matched.push(expr.as_str()),
            Ok(false) => {
                if all_must_match {
                    return (false, String::new());
                }
            }
            Err(e) => {
                tracing::debug!(expr = %expr, err = %e, "DSL evaluation error");
                if all_must_match {
                    return (false, String::new());
                }
            }
        }
    }
    if matched.is_empty() {
        (false, String::new())
    } else {
        (true, format!("dsl={matched:?}"))
    }
}

// ── XPath evaluation ──────────────────────────────────────────────────────────

fn apply_xpath(queries: &[String], all_must_match: bool, text: &str) -> (bool, String) {
    // Detect XML vs HTML by <?xml prefix
    let is_xml = text.trim_start().starts_with("<?xml") || text.trim_start().starts_with("<xml");

    let mut matched_queries = Vec::new();

    for query in queries {
        let hit = if is_xml {
            xpath_matches_xml(query, text)
        } else {
            xpath_matches_html(query, text)
        };

        if hit {
            matched_queries.push(query.as_str());
        } else if all_must_match {
            return (false, String::new());
        }
    }

    if matched_queries.is_empty() {
        (false, String::new())
    } else {
        (true, format!("xpath={matched_queries:?}"))
    }
}

fn xpath_matches_html(query: &str, html: &str) -> bool {
    // Use scraper for HTML parsing + CSS-like traversal.
    // For true XPath on HTML, convert simple XPath to CSS selector equivalent
    // or use sxd-xpath on the parsed document.
    use scraper::{Html, Selector};

    // Try CSS selector first (many Nuclei templates use CSS-compatible XPath)
    let css = xpath_to_css(query);
    if let Ok(sel) = Selector::parse(&css) {
        let doc = Html::parse_document(html);
        return doc.select(&sel).next().is_some();
    }

    // Fallback: try sxd-xpath on the HTML treated as XML
    xpath_matches_xml(query, html)
}

fn xpath_matches_xml(query: &str, xml: &str) -> bool {
    use sxd_document::parser;
    use sxd_xpath::evaluate_xpath;

    let package = match parser::parse(xml) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let document = package.as_document();
    match evaluate_xpath(&document, query) {
        Ok(val) => !matches!(val, sxd_xpath::Value::Nodeset(ref ns) if ns.size() == 0),
        Err(_) => false,
    }
}

/// Crude XPath → CSS selector conversion for common patterns.
/// Handles the most common Nuclei XPath forms used in detection templates.
fn xpath_to_css(xpath: &str) -> String {
    let mut css = xpath.to_string();
    css = css.replace("//", "");
    css = css.replace('/', " > ");
    css = css.replace("[@", "[");
    css.trim().to_string()
}

// ── Part text extraction ──────────────────────────────────────────────────────

pub fn response_part_text(resp: &ResponseData, part: &MatchPart) -> String {
    match part {
        MatchPart::Status => resp.status.to_string(),
        MatchPart::Body => resp.body.clone(),
        MatchPart::Headers => resp
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n"),
        MatchPart::Raw => {
            let headers = resp
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!("{}\n{}\n{}", resp.status, headers, resp.body)
        }
        MatchPart::Data => {
            String::from_utf8_lossy(resp.raw_bytes.as_deref().unwrap_or(resp.body.as_bytes()))
                .into_owned()
        }
        MatchPart::DnsAnswer => resp.extra.get("answer").cloned().unwrap_or_default(),
        MatchPart::DnsNs => resp.extra.get("ns").cloned().unwrap_or_default(),
        MatchPart::DnsExtra => resp.extra.get("extra").cloned().unwrap_or_default(),
        MatchPart::SslCert => resp.extra.get("certificate").cloned().unwrap_or_default(),
        MatchPart::WsResponse => resp.extra.get("response").cloned().unwrap_or_default(),
        MatchPart::All => {
            let headers = resp
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\n");
            let extra = resp.extra.values().cloned().collect::<Vec<_>>().join("\n");
            format!("{}\n{}\n{}\n{}", resp.status, headers, resp.body, extra)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> ResponseData {
        ResponseData {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            raw_bytes: None,
            extra: Default::default(),
        }
    }

    // ── Status ──────────────────────────────────────────────────────────────

    #[test]
    fn status_matcher_hits_correct_code() {
        let m = PatternMatcher {
            name: "ok".into(),
            matcher_type: MatcherType::Status {
                codes: vec![200, 201],
            },
            part: MatchPart::Status,
            negate: false,
        };
        let (matched, snippet) = m.apply(&resp(200, &[], ""));
        assert!(matched);
        assert!(snippet.contains("200"));
        assert!(!m.apply(&resp(404, &[], "")).0);
    }

    #[test]
    fn status_matcher_negate() {
        let m = PatternMatcher {
            name: "not-ok".into(),
            matcher_type: MatcherType::Status { codes: vec![200] },
            part: MatchPart::Status,
            negate: true,
        };
        assert!(!m.apply(&resp(200, &[], "")).0);
        assert!(m.apply(&resp(500, &[], "")).0);
    }

    // ── Words ───────────────────────────────────────────────────────────────

    #[test]
    fn words_matcher_body_case_sensitive() {
        let m = PatternMatcher {
            name: "body-word".into(),
            matcher_type: MatcherType::Words {
                words: vec!["Hello".into()],
                case_insensitive: false,
                all_must_match: false,
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.apply(&resp(200, &[], "Hello World")).0);
        assert!(!m.apply(&resp(200, &[], "hello world")).0);
    }

    #[test]
    fn words_matcher_all_must_match() {
        let m = PatternMatcher {
            name: "both".into(),
            matcher_type: MatcherType::Words {
                words: vec!["foo".into(), "bar".into()],
                case_insensitive: false,
                all_must_match: true,
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.apply(&resp(200, &[], "foo and bar")).0);
        assert!(!m.apply(&resp(200, &[], "only foo")).0);
    }

    // ── Regex ───────────────────────────────────────────────────────────────

    #[test]
    fn regex_matcher_captures_match() {
        let m = PatternMatcher {
            name: "version".into(),
            matcher_type: MatcherType::Regex {
                patterns: vec![r"nginx/\d+\.\d+".into()],
            },
            part: MatchPart::Headers,
            negate: false,
        };
        let r = resp(200, &[("server", "nginx/1.25.0")], "");
        let (matched, snippet) = m.apply(&r);
        assert!(matched);
        assert!(snippet.contains("nginx/1.25"));
    }

    #[test]
    fn validate_rejects_invalid_regex() {
        let m = PatternMatcher {
            name: "bad".into(),
            matcher_type: MatcherType::Regex {
                patterns: vec!["[invalid".into()],
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.validate().is_err());
    }

    // ── Binary ──────────────────────────────────────────────────────────────

    #[test]
    fn binary_matcher_hex_pattern() {
        let m = PatternMatcher {
            name: "hello-bytes".into(),
            matcher_type: MatcherType::Binary {
                patterns: vec!["48656c6c6f".into()], // "Hello"
                case_insensitive: false,
            },
            part: MatchPart::Body,
            negate: false,
        };
        let r = ResponseData {
            status: 200,
            headers: Default::default(),
            body: "Hello World".into(),
            raw_bytes: None,
            extra: Default::default(),
        };
        assert!(m.apply(&r).0);
    }

    #[test]
    fn binary_matcher_no_match() {
        let m = PatternMatcher {
            name: "not-there".into(),
            matcher_type: MatcherType::Binary {
                patterns: vec!["deadbeef".into()],
                case_insensitive: false,
            },
            part: MatchPart::Body,
            negate: false,
        };
        let r = ResponseData {
            status: 200,
            headers: Default::default(),
            body: "Hello World".into(),
            raw_bytes: None,
            extra: Default::default(),
        };
        assert!(!m.apply(&r).0);
    }

    #[test]
    fn validate_rejects_bad_hex() {
        let m = PatternMatcher {
            name: "bad-hex".into(),
            matcher_type: MatcherType::Binary {
                patterns: vec!["ZZZZ".into()],
                case_insensitive: false,
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.validate().is_err());
    }

    // ── Size ────────────────────────────────────────────────────────────────

    #[test]
    fn size_matcher_exact_match() {
        let m = PatternMatcher {
            name: "body-size".into(),
            matcher_type: MatcherType::Size { sizes: vec![5] },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.apply(&resp(200, &[], "hello")).0); // 5 bytes
        assert!(!m.apply(&resp(200, &[], "hi")).0); // 2 bytes
    }

    #[test]
    fn size_matcher_multiple_accepted() {
        let m = PatternMatcher {
            name: "body-size".into(),
            matcher_type: MatcherType::Size {
                sizes: vec![2, 5, 10],
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.apply(&resp(200, &[], "hi")).0);
        assert!(m.apply(&resp(200, &[], "hello")).0);
    }

    // ── DSL ─────────────────────────────────────────────────────────────────

    #[test]
    fn dsl_matcher_status_eq() {
        let m = PatternMatcher {
            name: "dsl-ok".into(),
            matcher_type: MatcherType::Dsl {
                expressions: vec!["status_code == 200".into()],
                all_must_match: false,
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.apply(&resp(200, &[], "")).0);
        assert!(!m.apply(&resp(404, &[], "")).0);
    }

    #[test]
    fn dsl_matcher_contains_body() {
        let m = PatternMatcher {
            name: "dsl-body".into(),
            matcher_type: MatcherType::Dsl {
                expressions: vec!["contains(body, \"admin\")".into()],
                all_must_match: false,
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.apply(&resp(200, &[], "admin panel")).0);
        assert!(!m.apply(&resp(200, &[], "user panel")).0);
    }

    // ── XPath ───────────────────────────────────────────────────────────────

    #[test]
    fn xpath_matcher_html_title() {
        let m = PatternMatcher {
            name: "has-title".into(),
            matcher_type: MatcherType::XPath {
                queries: vec!["//title".into()],
                all_must_match: false,
            },
            part: MatchPart::Body,
            negate: false,
        };
        let html = "<html><head><title>Welcome</title></head><body></body></html>";
        assert!(m.apply(&resp(200, &[], html)).0);
        assert!(
            !m.apply(&resp(200, &[], "<html><body>No title</body></html>"))
                .0
        );
    }
}

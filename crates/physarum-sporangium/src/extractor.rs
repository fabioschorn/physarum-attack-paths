//! Pattern extractors — ported from Nuclei `pkg/operators/extractors`.
//!
//! Ported extractor types:
//! - `regex` → [`ExtractorType::Regex`]  (capture group index)
//! - `kval`  → [`ExtractorType::Kval`]   (header/cookie key lookup)
//! - `json`  → [`ExtractorType::Json`]   (JSON pointer path)
//! - `xpath` → [`ExtractorType::XPath`]  (XPath 1.0 on HTML/XML)
//! - `dsl`   → [`ExtractorType::Dsl`]    (evalexpr string expressions)

use crate::runner::ResponseData;
use serde::{Deserialize, Serialize};

// ── ExtractedFact ─────────────────────────────────────────────────────────────

/// One extracted name→values pair from a response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractedFact {
    pub name: String,
    pub values: Vec<String>,
}

// ── ExtractPart ───────────────────────────────────────────────────────────────

/// Which part of the response to extract from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractPart {
    #[default]
    Body,
    Headers,
    Raw,
    DnsAnswer,
    DnsNs,
    SslCert,
    WsResponse,
}

// ── ExtractorType ─────────────────────────────────────────────────────────────

/// What extraction technique to apply — complete Nuclei extractor type set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ExtractorType {
    /// Extract via Rust regex with an optional capture group index.
    Regex {
        pattern: String,
        /// Capture group index. 0 = entire match, 1+ = numbered group.
        #[serde(default)]
        group: usize,
    },
    /// Extract a response header value by name (case-insensitive).
    Kval { key: String },
    /// Extract values using a `serde_json` pointer (e.g. `/data/0/id`).
    Json { pointer: String },
    /// Extract node text (or attribute) via XPath 1.0 query.
    XPath {
        /// XPath expression selecting target nodes.
        query: String,
        /// When set, return this attribute value instead of node inner text.
        #[serde(default)]
        attribute: Option<String>,
    },
    /// Evaluate an `evalexpr` expression and return the string result.
    Dsl { expression: String },
}

// ── PatternExtractor ──────────────────────────────────────────────────────────

/// A single extractor within a template. Immutable after load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternExtractor {
    /// Name used as the key in PatternFinding::extracted_facts.
    pub name: String,
    pub extractor_type: ExtractorType,
    #[serde(default)]
    pub part: ExtractPart,
    /// When true, extracted value is for internal variable chaining only
    /// and is not surfaced in the public PatternFinding.
    #[serde(default)]
    pub internal: bool,
}

impl PatternExtractor {
    /// Pre-validate at load time: compile regex patterns.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let ExtractorType::Regex { pattern, .. } = &self.extractor_type {
            regex::Regex::new(pattern).map_err(|e| {
                anyhow::anyhow!(
                    "extractor '{}': invalid regex {:?}: {}",
                    self.name,
                    pattern,
                    e
                )
            })?;
        }
        Ok(())
    }

    /// Extract facts from `resp`. Returns an `ExtractedFact` with zero or more values.
    pub fn apply(&self, resp: &ResponseData) -> ExtractedFact {
        let values = self.extract_values(resp);
        ExtractedFact {
            name: self.name.clone(),
            values,
        }
    }

    fn extract_values(&self, resp: &ResponseData) -> Vec<String> {
        match &self.extractor_type {
            ExtractorType::Regex { pattern, group } => {
                let text = extract_part_text(resp, &self.part);
                match regex::Regex::new(pattern) {
                    Ok(re) => re
                        .captures_iter(&text)
                        .filter_map(|cap| cap.get(*group).map(|m| m.as_str().to_string()))
                        .collect(),
                    Err(_) => vec![],
                }
            }

            ExtractorType::Kval { key } => {
                let lower_key = key.to_lowercase();
                resp.headers
                    .iter()
                    .filter(|(k, _)| k.to_lowercase() == lower_key)
                    .map(|(_, v)| v.clone())
                    .collect()
            }

            ExtractorType::Json { pointer } => {
                match serde_json::from_str::<serde_json::Value>(&resp.body) {
                    Ok(json) => match json.pointer(pointer) {
                        Some(serde_json::Value::String(s)) => vec![s.clone()],
                        Some(serde_json::Value::Number(n)) => vec![n.to_string()],
                        Some(serde_json::Value::Bool(b)) => vec![b.to_string()],
                        Some(serde_json::Value::Array(arr)) => {
                            arr.iter().map(|v| v.to_string()).collect()
                        }
                        Some(v) => vec![v.to_string()],
                        None => vec![],
                    },
                    Err(_) => vec![],
                }
            }

            ExtractorType::XPath { query, attribute } => {
                let text = extract_part_text(resp, &self.part);
                extract_xpath(&text, query, attribute.as_deref())
            }

            ExtractorType::Dsl { expression } => {
                let ctx = crate::dsl::build_dsl_context_from_response(resp);
                match crate::dsl::evaluate_dsl_string(expression, &ctx) {
                    Ok(s) if !s.is_empty() => vec![s],
                    _ => vec![],
                }
            }
        }
    }
}

// ── XPath extraction ──────────────────────────────────────────────────────────

fn extract_xpath(text: &str, query: &str, attribute: Option<&str>) -> Vec<String> {
    let is_xml = text.trim_start().starts_with("<?xml") || text.trim_start().starts_with("<xml");

    if is_xml {
        extract_xpath_xml(text, query, attribute)
    } else {
        extract_xpath_html(text, query, attribute)
    }
}

fn extract_xpath_html(html: &str, query: &str, attribute: Option<&str>) -> Vec<String> {
    use scraper::{Html, Selector};

    // Convert XPath to CSS selector for HTML
    let css = xpath_to_css(query);
    if let Ok(sel) = Selector::parse(&css) {
        let doc = Html::parse_document(html);
        return doc
            .select(&sel)
            .map(|el| {
                if let Some(attr) = attribute {
                    el.value().attr(attr).unwrap_or("").to_string()
                } else {
                    el.text().collect::<String>()
                }
            })
            .filter(|s| !s.is_empty())
            .collect();
    }

    // Fallback to XML XPath parser
    extract_xpath_xml(html, query, attribute)
}

fn extract_xpath_xml(xml: &str, query: &str, _attribute: Option<&str>) -> Vec<String> {
    use sxd_document::parser;
    use sxd_xpath::{evaluate_xpath, Value};

    let package = match parser::parse(xml) {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    let document = package.as_document();
    match evaluate_xpath(&document, query) {
        Ok(Value::Nodeset(ns)) => {
            let mut results = Vec::new();
            for node in ns.document_order() {
                let text = match node {
                    sxd_xpath::nodeset::Node::Element(el) => {
                        // Collect all text children
                        el.children()
                            .into_iter()
                            .filter_map(|c| {
                                if let sxd_document::dom::ChildOfElement::Text(t) = c {
                                    Some(t.text().to_string())
                                } else {
                                    None
                                }
                            })
                            .collect::<String>()
                    }
                    sxd_xpath::nodeset::Node::Text(t) => t.text().to_string(),
                    sxd_xpath::nodeset::Node::Attribute(a) => a.value().to_string(),
                    _ => continue,
                };
                if !text.is_empty() {
                    results.push(text);
                }
            }
            results
        }
        Ok(Value::String(s)) => {
            if s.is_empty() {
                vec![]
            } else {
                vec![s]
            }
        }
        Ok(v) => vec![v.string()],
        Err(_) => vec![],
    }
}

/// Crude XPath → CSS selector conversion for common patterns.
fn xpath_to_css(xpath: &str) -> String {
    let mut css = xpath.to_string();
    css = css.replace("//", "");
    css = css.replace('/', " > ");
    css = css.replace("[@", "[");
    css.trim().to_string()
}

// ── Part text extraction ──────────────────────────────────────────────────────

fn extract_part_text(resp: &ResponseData, part: &ExtractPart) -> String {
    match part {
        ExtractPart::Body => resp.body.clone(),
        ExtractPart::Headers => resp
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n"),
        ExtractPart::Raw => {
            let headers = resp
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!("{}\n{}\n{}", resp.status, headers, resp.body)
        }
        ExtractPart::DnsAnswer => resp.extra.get("answer").cloned().unwrap_or_default(),
        ExtractPart::DnsNs => resp.extra.get("ns").cloned().unwrap_or_default(),
        ExtractPart::SslCert => resp.extra.get("certificate").cloned().unwrap_or_default(),
        ExtractPart::WsResponse => resp.extra.get("response").cloned().unwrap_or_default(),
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

    #[test]
    fn regex_extractor_group_0_full_match() {
        let ex = PatternExtractor {
            name: "version".into(),
            extractor_type: ExtractorType::Regex {
                pattern: r"nginx/[\d.]+".into(),
                group: 0,
            },
            part: ExtractPart::Headers,
            internal: false,
        };
        let r = resp(200, &[("server", "nginx/1.25.0")], "");
        let fact = ex.apply(&r);
        assert_eq!(fact.values, vec!["nginx/1.25.0"]);
    }

    #[test]
    fn regex_extractor_capture_group_1() {
        let ex = PatternExtractor {
            name: "title".into(),
            extractor_type: ExtractorType::Regex {
                pattern: r"<title>([^<]+)</title>".into(),
                group: 1,
            },
            part: ExtractPart::Body,
            internal: false,
        };
        let r = resp(200, &[], "<html><title>Welcome</title></html>");
        assert_eq!(ex.apply(&r).values, vec!["Welcome"]);
    }

    #[test]
    fn kval_extractor_case_insensitive_header() {
        let ex = PatternExtractor {
            name: "server-header".into(),
            extractor_type: ExtractorType::Kval {
                key: "Server".into(),
            },
            part: ExtractPart::Headers,
            internal: false,
        };
        let r = resp(200, &[("server", "nginx/1.25")], "");
        assert_eq!(ex.apply(&r).values, vec!["nginx/1.25"]);
    }

    #[test]
    fn json_extractor_pointer_path() {
        let ex = PatternExtractor {
            name: "item-id".into(),
            extractor_type: ExtractorType::Json {
                pointer: "/id".into(),
            },
            part: ExtractPart::Body,
            internal: false,
        };
        let r = resp(200, &[], r#"{"id": "abc123"}"#);
        assert_eq!(ex.apply(&r).values, vec!["abc123"]);
    }

    #[test]
    fn dsl_extractor_evaluates_expression() {
        let ex = PatternExtractor {
            name: "server-lower".into(),
            extractor_type: ExtractorType::Dsl {
                expression: "tolower(header_server)".into(),
            },
            part: ExtractPart::Body,
            internal: false,
        };
        let r = resp(200, &[("server", "NGINX/1.25")], "");
        let fact = ex.apply(&r);
        assert_eq!(fact.values, vec!["nginx/1.25"]);
    }

    #[test]
    fn xpath_extractor_html_text() {
        let ex = PatternExtractor {
            name: "page-title".into(),
            extractor_type: ExtractorType::XPath {
                query: "//title".into(),
                attribute: None,
            },
            part: ExtractPart::Body,
            internal: false,
        };
        let r = resp(200, &[], "<html><head><title>My Page</title></head></html>");
        let fact = ex.apply(&r);
        assert_eq!(fact.values, vec!["My Page"]);
    }

    #[test]
    fn validate_rejects_invalid_regex() {
        let ex = PatternExtractor {
            name: "bad".into(),
            extractor_type: ExtractorType::Regex {
                pattern: "[broken".into(),
                group: 0,
            },
            part: ExtractPart::Body,
            internal: false,
        };
        assert!(ex.validate().is_err());
    }
}

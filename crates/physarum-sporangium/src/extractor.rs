use crate::runner::ResponseData;
use serde::{Deserialize, Serialize};

/// One extracted name→values pair from a response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractedFact {
    pub name: String,
    pub values: Vec<String>,
}

/// Which part of the response to extract from.
/// Mirrors Nuclei's `part` field on extractors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractPart {
    #[default]
    Body,
    Headers,
    Raw,
}

/// What extraction technique to apply.
///
/// Nuclei extractor types ported:
/// - `regex` → Regex (with capture group)
/// - `kval`  → KVal  (header/cookie key lookup)
/// - `json`  → Json  (serde_json pointer path)
///
/// Planned but not in scope for first PR: XPath, DSL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ExtractorType {
    Regex {
        pattern: String,
        /// Capture group index to return. 0 = entire match, 1+ = named groups.
        #[serde(default)]
        group: usize,
    },
    /// Extract a header value by name (case-insensitive).
    Kval { key: String },
    /// Extract values using a serde_json pointer (e.g. `/data/0/id`).
    Json { pointer: String },
}

/// A single extractor within a template. Immutable after load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternExtractor {
    /// Name used as the key in PatternFinding::extracted_facts.
    pub name: String,
    pub extractor_type: ExtractorType,
    #[serde(default)]
    pub part: ExtractPart,
    /// If true, the extracted value is for internal use only (e.g. chaining into next
    /// request) and should not appear in the public finding. Not used in first PR.
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
        let values = match &self.extractor_type {
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
                        Some(serde_json::Value::Array(arr)) => {
                            arr.iter().map(|v| v.to_string()).collect()
                        }
                        Some(v) => vec![v.to_string()],
                        None => vec![],
                    },
                    Err(_) => vec![],
                }
            }
        };

        ExtractedFact {
            name: self.name.clone(),
            values,
        }
    }
}

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
    }
}

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
        assert_eq!(fact.name, "version");
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
        let fact = ex.apply(&r);
        assert_eq!(fact.values, vec!["Welcome"]);
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
        let fact = ex.apply(&r);
        assert_eq!(fact.values, vec!["nginx/1.25"]);
    }

    #[test]
    fn kval_extractor_missing_header_returns_empty() {
        let ex = PatternExtractor {
            name: "x-powered-by".into(),
            extractor_type: ExtractorType::Kval {
                key: "x-powered-by".into(),
            },
            part: ExtractPart::Headers,
            internal: false,
        };
        let r = resp(200, &[], "");
        assert!(ex.apply(&r).values.is_empty());
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
        let r = resp(200, &[], r#"{"id": "abc123", "name": "test"}"#);
        let fact = ex.apply(&r);
        assert_eq!(fact.values, vec!["abc123"]);
    }

    #[test]
    fn json_extractor_invalid_body_returns_empty() {
        let ex = PatternExtractor {
            name: "data".into(),
            extractor_type: ExtractorType::Json {
                pointer: "/data".into(),
            },
            part: ExtractPart::Body,
            internal: false,
        };
        let r = resp(200, &[], "not json");
        assert!(ex.apply(&r).values.is_empty());
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

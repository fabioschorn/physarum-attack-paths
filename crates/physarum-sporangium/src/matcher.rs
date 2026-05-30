use crate::runner::ResponseData;
use serde::{Deserialize, Serialize};

/// Whether all matchers must pass (AND) or any one suffices (OR).
/// Nuclei default is OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    And,
    #[default]
    Or,
}

/// Which part of the response to test against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
}

/// What the matcher tests for.
///
/// Nuclei matcher types ported:
/// - `status`  → Status
/// - `word`    → Words
/// - `regex`   → Regex
///
/// Planned but not in scope for first PR: Binary, DSL, XPath.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MatcherType {
    Status {
        codes: Vec<u16>,
    },
    Words {
        words: Vec<String>,
        #[serde(default)]
        case_insensitive: bool,
        /// If true, all words must appear (Nuclei `condition: and` inside words).
        #[serde(default)]
        all_must_match: bool,
    },
    Regex {
        patterns: Vec<String>,
    },
}

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
        if let MatcherType::Regex { patterns } = &self.matcher_type {
            for p in patterns {
                regex::Regex::new(p).map_err(|e| {
                    anyhow::anyhow!("matcher '{}': invalid regex {:?}: {}", self.name, p, e)
                })?;
            }
        }
        Ok(())
    }

    /// Apply this matcher to `resp`. Returns `(matched, snippet)`.
    /// `snippet` is an excerpt describing what triggered the match (empty if no match).
    pub fn apply(&self, resp: &ResponseData) -> (bool, String) {
        let (raw_matched, snippet) = self.apply_inner(resp);
        let matched = if self.negate {
            !raw_matched
        } else {
            raw_matched
        };
        (matched, snippet)
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
                    // Patterns validated at load time; unwrap is safe.
                    if let Ok(re) = regex::Regex::new(pattern) {
                        if let Some(m) = re.find(&text) {
                            return (true, format!("regex={:?}", m.as_str()));
                        }
                    }
                }
                (false, String::new())
            }
        }
    }
}

fn response_part_text(resp: &ResponseData, part: &MatchPart) -> String {
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

        let (matched, _) = m.apply(&resp(404, &[], ""));
        assert!(!matched);
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
    fn words_matcher_headers_case_insensitive() {
        let m = PatternMatcher {
            name: "server-nginx".into(),
            matcher_type: MatcherType::Words {
                words: vec!["nginx".into()],
                case_insensitive: true,
                all_must_match: false,
            },
            part: MatchPart::Headers,
            negate: false,
        };
        let r = resp(200, &[("server", "nginx/1.25")], "");
        assert!(m.apply(&r).0);

        let r2 = resp(200, &[("server", "Apache/2.4")], "");
        assert!(!m.apply(&r2).0);
    }

    #[test]
    fn words_matcher_all_must_match() {
        let m = PatternMatcher {
            name: "both-words".into(),
            matcher_type: MatcherType::Words {
                words: vec!["foo".into(), "bar".into()],
                case_insensitive: false,
                all_must_match: true,
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.apply(&resp(200, &[], "foo and bar here")).0);
        assert!(!m.apply(&resp(200, &[], "only foo here")).0);
    }

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

    #[test]
    fn validate_accepts_valid_regex() {
        let m = PatternMatcher {
            name: "ok".into(),
            matcher_type: MatcherType::Regex {
                patterns: vec![r"\d+".into()],
            },
            part: MatchPart::Body,
            negate: false,
        };
        assert!(m.validate().is_ok());
    }
}

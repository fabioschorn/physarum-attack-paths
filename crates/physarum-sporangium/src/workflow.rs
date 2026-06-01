//! Workflow engine — ported from Nuclei `pkg/workflows`.
//!
//! Executes multi-step template chains where the output of one template
//! (matched names, extracted values) determines which subtemplates to run next.
//!
//! # Workflow definition
//!
//! A workflow is a list of [`WorkflowStep`]s. Each step has:
//! - A template to run first.
//! - Optional matchers: if any matcher name appears in the template's findings,
//!   run the associated subtemplates with the extracted variables injected.
//!
//! # Example
//!
//! ```yaml
//! workflows:
//!   - template: http/detect/nginx-detect.yaml
//!     matchers:
//!       - name: ["nginx-header"]
//!         subtemplates:
//!           - template: http/cve/nginx-cve-2021.yaml
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::finding::PatternFinding;

// ── Workflow types ────────────────────────────────────────────────────────────

/// Condition type within a workflow matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkflowCondition {
    /// Any one of the names must match (OR).
    #[default]
    Or,
    /// All names must match (AND).
    And,
}

/// A matcher within a workflow step — triggers subtemplates when
/// the specified matcher/extractor names appear in findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowMatcher {
    /// Matcher or extractor names to look for in the parent template's output.
    pub name: Vec<String>,
    #[serde(default)]
    pub condition: WorkflowCondition,
    /// Templates to run when this matcher fires.
    pub subtemplates: Vec<WorkflowStep>,
}

/// A single step in a workflow chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Template ID or path to execute.
    pub template: String,
    /// Matcher conditions that trigger sub-workflows.
    #[serde(default)]
    pub matchers: Vec<WorkflowMatcher>,
    /// Tags used to filter templates when `template` points to a directory.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A complete workflow definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub steps: Vec<WorkflowStep>,
}

// ── WorkflowResult ────────────────────────────────────────────────────────────

/// Aggregated output from running a workflow.
#[derive(Debug, Default)]
pub struct WorkflowResult {
    /// All findings from all templates in the chain.
    pub findings: Vec<PatternFinding>,
    /// All extracted variables accumulated across steps.
    pub variables: HashMap<String, String>,
}

impl WorkflowResult {
    pub fn merge(&mut self, other: WorkflowResult) {
        self.findings.extend(other.findings);
        self.variables.extend(other.variables);
    }
}

// ── Workflow execution ────────────────────────────────────────────────────────

/// Evaluate whether a set of findings satisfies a [`WorkflowMatcher`].
///
/// Returns `true` when the findings contain the matcher names (respecting
/// the AND/OR condition) AND the matcher condition.
pub fn matcher_fires(wm: &WorkflowMatcher, findings: &[PatternFinding]) -> bool {
    let present_names: std::collections::HashSet<&str> = findings
        .iter()
        .flat_map(|f| {
            // Collect matcher names from summary + extractor names from facts
            let mut names: Vec<&str> = f
                .extracted_facts
                .iter()
                .map(|ef| ef.name.as_str())
                .collect();
            // Parse matcher names from summary like "nginx-header: ..."
            for part in f.matched_condition_summary.split(';') {
                if let Some(name) = part.trim().split(':').next() {
                    names.push(name.trim());
                }
            }
            names
        })
        .collect();

    match wm.condition {
        WorkflowCondition::Or => wm.name.iter().any(|n| present_names.contains(n.as_str())),
        WorkflowCondition::And => wm.name.iter().all(|n| present_names.contains(n.as_str())),
    }
}

/// Extract variables from findings to pass into subtemplates.
///
/// Converts extracted facts into template variables with the fact name
/// as key and the first value as the variable value.
pub fn extract_variables_from_findings(findings: &[PatternFinding]) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for finding in findings {
        for fact in &finding.extracted_facts {
            if let Some(first) = fact.values.first() {
                vars.insert(fact.name.clone(), first.clone());
            }
        }
    }
    vars
}

/// Check if a [`WorkflowStep`] should run against a set of parent findings
/// and return the inherited variable context if so.
///
/// This is the pure logic layer — actual template execution is handled by
/// the caller (typically `PatternRunner` or the maze agent's LLM loop)
/// since it requires async network I/O.
pub fn should_run_subtemplate(
    step: &WorkflowStep,
    parent_findings: &[PatternFinding],
    parent_vars: &HashMap<String, String>,
) -> Option<(String, HashMap<String, String>)> {
    // Collect variables that would be passed to this step
    let mut vars = parent_vars.clone();
    let extracted = extract_variables_from_findings(parent_findings);
    vars.extend(extracted);

    // A step with no matchers always runs
    if step.matchers.is_empty() {
        return Some((step.template.clone(), vars));
    }

    // At least one WorkflowMatcher must fire (OR between matchers)
    for wm in &step.matchers {
        if matcher_fires(wm, parent_findings) {
            return Some((step.template.clone(), vars));
        }
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractor::ExtractedFact;
    use crate::finding::EvidenceSource;
    use crate::template::{PatternProtocol, SeverityHint};
    use chrono::Utc;

    fn finding_with_matcher(name: &str, matcher_summary: &str) -> PatternFinding {
        PatternFinding {
            template_id: "test".into(),
            check_id: "test".into(),
            name: "Test".into(),
            target_ip: "127.0.0.1".parse().unwrap(),
            port: 80,
            protocol: PatternProtocol::Http,
            severity_hint: SeverityHint::Info,
            confidence: 1.0,
            matched_condition_summary: matcher_summary.to_string(),
            extracted_facts: vec![ExtractedFact {
                name: name.to_string(),
                values: vec!["value".into()],
            }],
            evidence_source: EvidenceSource::HttpProbe,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn matcher_fires_or_condition() {
        let wm = WorkflowMatcher {
            name: vec!["nginx-header".into(), "apache-header".into()],
            condition: WorkflowCondition::Or,
            subtemplates: vec![],
        };
        let findings = vec![finding_with_matcher(
            "nginx-header",
            "nginx-header: words=[nginx]",
        )];
        assert!(matcher_fires(&wm, &findings));
    }

    #[test]
    fn matcher_fires_and_condition_requires_all() {
        let wm = WorkflowMatcher {
            name: vec!["fact-a".into(), "fact-b".into()],
            condition: WorkflowCondition::And,
            subtemplates: vec![],
        };
        let only_a = vec![finding_with_matcher("fact-a", "fact-a: ok")];
        assert!(!matcher_fires(&wm, &only_a));

        let both = vec![
            finding_with_matcher("fact-a", "fact-a: ok"),
            finding_with_matcher("fact-b", "fact-b: ok"),
        ];
        assert!(matcher_fires(&wm, &both));
    }

    #[test]
    fn should_run_subtemplate_no_matchers_always_runs() {
        let step = WorkflowStep {
            template: "cve-check.yaml".into(),
            matchers: vec![],
            tags: vec![],
        };
        let result = should_run_subtemplate(&step, &[], &HashMap::new());
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "cve-check.yaml");
    }

    #[test]
    fn extract_variables_from_facts() {
        let findings = vec![finding_with_matcher("server-version", "server: ok")];
        let vars = extract_variables_from_findings(&findings);
        assert_eq!(vars.get("server-version").unwrap(), "value");
    }
}

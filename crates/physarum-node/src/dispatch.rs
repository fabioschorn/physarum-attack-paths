use anyhow::{Context, Result};
use physarum_node_runtime::NodeCapability;
use physarum_probe::probe::ProbeConfig;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::cli::Cli;

pub async fn run(cli: Cli) -> Result<()> {
    if !cli.capabilities.contains(&NodeCapability::Probe) {
        anyhow::bail!(
            "--capabilities must include 'probe'; got: {:?}",
            cli.capabilities
        );
    }

    tracing::info!(
        capabilities = ?cli.capabilities,
        id = %cli.id,
        coordinator = %cli.coordinator,
        "physarum-node starting"
    );

    let mut set = tokio::task::JoinSet::new();

    // Probe capability — run inline (Gate M.4: no subprocess).
    let probe_cfg = build_probe_config(&cli);
    tracing::info!(capability = "probe", "running probe capability inline");
    set.spawn(async move { physarum_probe::probe::run(probe_cfg).await });

    // ObserveEbpf (observe-flow) — delegate to physarum-ebpf-observer subprocess.
    if cli.capabilities.contains(&NodeCapability::ObserveEbpf) {
        let bin_dir = sibling_bin_dir()?;
        let obs_cmd = build_flow_observer_cmd(&cli, &bin_dir)?;
        set.spawn(supervise("physarum-ebpf-observer", obs_cmd));
    }

    // ObservePacket (observe-packet) — delegate to physarum-packet-observer subprocess.
    if cli.capabilities.contains(&NodeCapability::ObservePacket) {
        let bin_dir = sibling_bin_dir()?;
        let pkt_cmd = build_packet_observer_cmd(&cli, &bin_dir)?;
        set.spawn(supervise("physarum-packet-observer", pkt_cmd));
    }

    // A node exits only when a capability task exits unexpectedly.
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(join_err) => return Err(join_err.into()),
        }
    }

    Ok(())
}

fn build_probe_config(cli: &Cli) -> ProbeConfig {
    ProbeConfig {
        id: cli.id.clone(),
        coordinator: cli.coordinator.clone(),
        listen: cli.listen,
        advertise_address: cli.advertise_address.clone(),
        probe_interval_seconds: cli.probe_interval_seconds,
        synthetic_failure_rate: cli.synthetic_failure_rate,
        probe_targets: cli.probe_targets.clone(),
        discovery_enabled: cli.discovery_enabled,
        discovery_cidrs: cli.discovery_cidrs.clone(),
        discovery_ports: cli.discovery_ports.clone(),
        discovery_interval_secs: cli.discovery_interval_secs,
        discovery_max_candidates: cli.discovery_max_candidates,
        discovery_timeout_ms: cli.discovery_timeout_ms,
        discovery_seed_cooldown_secs: cli.discovery_seed_cooldown_secs,
        discovery_scope_mode: cli.discovery_scope_mode.clone(),
        sense_tcp_socket_state: cli.sense_tcp_socket_state,
        sense_icmp_packet: cli.sense_icmp_packet,
    }
}

/// Locate sibling executables — same directory as the running physarum-node binary.
fn sibling_bin_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot determine physarum-node executable path")?;
    exe.parent()
        .map(Path::to_path_buf)
        .context("physarum-node executable has no parent directory")
}

fn sibling(bin_dir: &Path, name: &str) -> PathBuf {
    bin_dir.join(name)
}

fn build_flow_observer_cmd(cli: &Cli, bin_dir: &Path) -> Result<Command> {
    let mut cmd = Command::new(sibling(bin_dir, "physarum-ebpf-observer"));
    cmd.arg("--agent-id")
        .arg(&cli.id)
        .arg("--coordinator-url")
        .arg(&cli.coordinator);
    if let Some(bytecode) = &cli.flow_bpf_bytecode {
        cmd.arg("--bpf-bytecode").arg(bytecode);
    }
    if cli.flow_filter_port != 0 {
        cmd.arg("--filter-port")
            .arg(cli.flow_filter_port.to_string());
    }
    Ok(cmd)
}

fn build_packet_observer_cmd(cli: &Cli, bin_dir: &Path) -> Result<Command> {
    let mut cmd = Command::new(sibling(bin_dir, "physarum-packet-observer"));
    cmd.arg("--agent-id")
        .arg(&cli.id)
        .arg("--coordinator-url")
        .arg(&cli.coordinator)
        .arg("--interface")
        .arg(&cli.interface);
    if let Some(bytecode) = &cli.packet_bpf_bytecode {
        cmd.arg("--bpf-bytecode").arg(bytecode);
    }
    Ok(cmd)
}

/// Run a child process and wait for it. Returns Err if the process exits with
/// a non-zero status or cannot be spawned.
async fn supervise(name: &'static str, mut cmd: Command) -> Result<()> {
    tracing::info!(binary = name, "spawning capability subprocess");
    let status = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {name}"))?
        .wait()
        .await
        .with_context(|| format!("failed to wait for {name}"))?;

    if status.success() {
        tracing::info!(binary = name, "capability subprocess exited cleanly");
        Ok(())
    } else {
        Err(anyhow::anyhow!("{name} exited with status {status}"))
    }
}

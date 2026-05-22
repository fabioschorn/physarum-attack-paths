use anyhow::{Context, Result};
use physarum_node_runtime::NodeCapability;
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

    let bin_dir = sibling_bin_dir()?;

    tracing::info!(
        capabilities = ?cli.capabilities,
        id = %cli.id,
        coordinator = %cli.coordinator,
        "physarum-node starting"
    );

    let mut set = tokio::task::JoinSet::new();

    // Probe capability — delegate to physarum-agent.
    let agent_cmd = build_agent_cmd(&cli, &bin_dir)?;
    set.spawn(supervise("physarum-agent", agent_cmd));

    // ObserveEbpf (observe-flow) capability — delegate to physarum-ebpf-observer.
    if cli.capabilities.contains(&NodeCapability::ObserveEbpf) {
        let obs_cmd = build_flow_observer_cmd(&cli, &bin_dir)?;
        set.spawn(supervise("physarum-ebpf-observer", obs_cmd));
    }

    // ObservePacket (observe-packet) capability — delegate to physarum-packet-observer.
    if cli.capabilities.contains(&NodeCapability::ObservePacket) {
        let pkt_cmd = build_packet_observer_cmd(&cli, &bin_dir)?;
        set.spawn(supervise("physarum-packet-observer", pkt_cmd));
    }

    // A node exits only when a supervised capability exits unexpectedly.
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(join_err) => return Err(join_err.into()),
        }
    }

    Ok(())
}

/// Locate sibling executables — same directory as the running physarum-node binary.
/// In production: /usr/local/bin/. In dev: target/debug/ or target/release/.
fn sibling_bin_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot determine physarum-node executable path")?;
    exe.parent()
        .map(Path::to_path_buf)
        .context("physarum-node executable has no parent directory")
}

fn sibling(bin_dir: &Path, name: &str) -> PathBuf {
    bin_dir.join(name)
}

fn build_agent_cmd(cli: &Cli, bin_dir: &Path) -> Result<Command> {
    let mut cmd = Command::new(sibling(bin_dir, "physarum-agent"));
    cmd.arg("--id")
        .arg(&cli.id)
        .arg("--coordinator")
        .arg(&cli.coordinator)
        .arg("--listen")
        .arg(cli.listen.to_string())
        .arg("--advertise-address")
        .arg(&cli.advertise_address)
        .arg("--probe-interval-seconds")
        .arg(cli.probe_interval_seconds.to_string());
    Ok(cmd)
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
        Err(anyhow::anyhow!("{name} exited with status {status}",))
    }
}

/// SSH + SCP propagation via sshpass (empty-password auth model).
///
/// The lab hosts have:
///   - passwd -d ec2-user  (empty password)
///   - sshd Match Address <src_ip> { PermitEmptyPasswords yes }
///   - AllowUsers ec2-user@<src_ip>
///
/// So the organism's source IP *is* its credential.  sshpass -p "" sends
/// an empty password, and the sshd Match block accepts it from the allowed IP.
use anyhow::Result;
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::process::Command;

const REMOTE_BIN: &str = "/tmp/physarum-maze";
const REMOTE_LOG: &str = "/tmp/physarum-maze.log";

pub enum Outcome {
    Success,
    ScpFailed,
    SshFailed,
}

/// Push binary to `target` via SCP and launch the propagated instance.
///
/// Returns `Outcome::ScpFailed` when SCP is rejected (sshd AllowUsers blocks
/// us at the OS level — this is how the dead-end / wrong-source detection works).
pub async fn propagate(target: Ipv4Addr, local_bin: &Path, lineage_b64: &str) -> Result<Outcome> {
    let target_s = target.to_string();
    let local_bin_s = local_bin
        .to_str()
        .unwrap_or(REMOTE_BIN);

    // ── Step 1: SCP binary to remote ─────────────────────────────────────────
    tracing::info!(%target, "SCP binary");

    let scp_ok = Command::new("sshpass")
        .args([
            "-p",
            "",
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            local_bin_s,
            &format!("ec2-user@{}:{}", target_s, REMOTE_BIN),
        ])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    if !scp_ok {
        tracing::warn!(%target, "SCP rejected — sshd AllowUsers blocked us (dead end)");
        return Ok(Outcome::ScpFailed);
    }

    // ── Step 2: SSH launch propagated instance (nohup, detached) ─────────────
    tracing::info!(%target, "SSH launch");

    // Run as root so the binary can open a raw ICMP socket.
    // systemd-run --no-block creates a transient unit completely detached from the
    // SSH session — no parent wait, no fd inheritance, returns immediately.
    let remote_cmd = format!(
        "chmod +x {bin} && sudo systemd-run --no-block --collect --unit=physarum-maze {bin} --mode propagated --lineage-b64 {b64}",
        bin = REMOTE_BIN,
        b64 = lineage_b64,
    );

    let ssh_ok = Command::new("sshpass")
        .args([
            "-p",
            "",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "BatchMode=no",
            &format!("ec2-user@{}", target_s),
            &remote_cmd,
        ])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    if ssh_ok {
        Ok(Outcome::Success)
    } else {
        tracing::warn!(%target, "SSH launch failed");
        Ok(Outcome::SshFailed)
    }
}

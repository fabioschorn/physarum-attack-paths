// This module is compiled only on Linux where eBPF is available.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use tokio::io::unix::AsyncFd;

use crate::{config::Config, mapper, submitter::Submitter};

pub async fn run(config: &Config) -> Result<()> {
    let bytecode_path = config
        .bpf_bytecode
        .as_ref()
        .context("--bpf-bytecode <path> is required on Linux (compile physarum-ebpf-observer-ebpf with cargo xtask build-ebpf)")?;

    let bytecode = std::fs::read(bytecode_path)
        .with_context(|| format!("failed to read eBPF bytecode: {}", bytecode_path.display()))?;

    let mut bpf = Ebpf::load(&bytecode)?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        tracing::warn!("eBPF kernel logger unavailable: {e}");
    }

    let program: &mut TracePoint = bpf
        .program_mut("physarum_observer")
        .context("eBPF program 'physarum_observer' not found in bytecode")?
        .try_into()
        .context("expected a TracePoint program")?;

    program.load().context("failed to load eBPF program")?;
    program
        .attach("sock", "inet_sock_set_state")
        .context("failed to attach to sock/inet_sock_set_state tracepoint")?;

    tracing::info!(
        agent_id = %config.agent_id,
        dry_run  = config.dry_run,
        "observer attached to tracepoint/sock/inet_sock_set_state"
    );

    let submitter = Submitter::new(&config.coordinator_url, config.server_timeout_ms)?;

    let ring_map = bpf
        .take_map("EVENTS")
        .context("ring buffer map 'EVENTS' not found in bytecode")?;
    let ring_buf = RingBuf::try_from(ring_map)?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let rb = guard.get_inner_mut();

        while let Some(bytes) = rb.next() {
            let Some(event) = parse_event(&bytes) else {
                continue;
            };

            if config.filter_port != 0 && event.dst_port != config.filter_port {
                continue;
            }

            let obs = mapper::map(&event, &config.agent_id);

            tracing::debug!(
                src      = %obs.source_ip,
                dst      = %obs.destination_ip,
                dst_port = obs.destination_port,
                event    = ?obs.event,
                comm     = %obs.comm,
                pid      = obs.pid,
                "flow event captured"
            );

            if config.dry_run {
                tracing::info!(
                    src      = %obs.source_ip,
                    dst      = %obs.destination_ip,
                    dst_port = obs.destination_port,
                    event    = ?obs.event,
                    "dry-run: skipping POST"
                );
            } else if let Err(e) = submitter.submit(&obs).await {
                tracing::warn!("submit failed: {e}");
            }
        }

        guard.clear_ready();
    }
}

fn parse_event(bytes: &[u8]) -> Option<mapper::TcpEvent> {
    if bytes.len() < core::mem::size_of::<mapper::TcpEvent>() {
        tracing::warn!(
            got = bytes.len(),
            want = core::mem::size_of::<mapper::TcpEvent>(),
            "ring buffer entry too small — possible ABI mismatch"
        );
        return None;
    }
    // Safety: TcpEvent is #[repr(C)] with only plain integer fields;
    // the eBPF program wrote exactly this layout into the ring buffer.
    Some(unsafe { *(bytes.as_ptr() as *const mapper::TcpEvent) })
}

// This module is compiled only on Linux where eBPF is available.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use aya::{
    maps::RingBuf,
    programs::tc::{qdisc_add_clsact, SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use tokio::io::unix::AsyncFd;

use crate::{config::Config, mapper, submitter::Submitter};

pub async fn run(config: &Config) -> Result<()> {
    let bytecode_path = config.bpf_bytecode.as_ref().context(
        "--bpf-bytecode <path> is required on Linux \
         (compile physarum-packet-observer-ebpf with cargo xtask build-ebpf-packet)",
    )?;

    let bytecode = std::fs::read(bytecode_path)
        .with_context(|| format!("failed to read eBPF bytecode: {}", bytecode_path.display()))?;

    let mut bpf = Ebpf::load(&bytecode)?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        tracing::warn!("eBPF kernel logger unavailable: {e}");
    }

    // ── tc ingress lifecycle ──────────────────────────────────────────────────
    //
    // clsact qdisc must exist before attaching a tc classifier.  Creating it
    // twice returns EEXIST, which we treat as success (idempotent on restart).
    match qdisc_add_clsact(&config.interface) {
        Ok(()) => tracing::info!(
            interface = %config.interface,
            "clsact qdisc created"
        ),
        Err(e) => tracing::warn!(
            interface = %config.interface,
            "clsact qdisc may already exist (safe to ignore on restart): {e}"
        ),
    }

    let program: &mut SchedClassifier = bpf
        .program_mut("physarum_icmp_observer")
        .context("eBPF program 'physarum_icmp_observer' not found in bytecode")?
        .try_into()
        .context("expected a SchedClassifier program")?;

    program.load().context("failed to load eBPF program")?;

    // Attach to ingress queue of the configured interface.
    // If a stale link exists from a previous run that was not cleanly
    // detached, aya returns an error.  We log it and bail — the operator
    // should remove the stale link via `tc filter del dev <iface> ingress`
    // or simply reboot/restart the service via systemd (which will clean up).
    program
        .attach(&config.interface, TcAttachType::Ingress)
        .with_context(|| {
            format!(
                "failed to attach tc ingress classifier to {}. \
                 If a stale link exists, run: tc filter del dev {} ingress",
                config.interface, config.interface
            )
        })?;

    tracing::info!(
        agent_id  = %config.agent_id,
        interface = %config.interface,
        dry_run   = config.dry_run,
        "packet observer attached to tc ingress"
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

            let obs = mapper::map(&event, &config.agent_id, &config.interface);

            tracing::debug!(
                src       = %obs.source_ip,
                dst       = %obs.destination_ip,
                icmp_type = ?obs.icmp_type,
                iface     = %obs.interface_name,
                "ICMP packet captured"
            );

            if config.dry_run {
                tracing::info!(
                    src       = %obs.source_ip,
                    dst       = %obs.destination_ip,
                    icmp_type = ?obs.icmp_type,
                    "dry-run: skipping POST"
                );
            } else if let Err(e) = submitter.submit(&obs).await {
                tracing::warn!("submit failed: {e}");
            }
        }

        guard.clear_ready();
    }
}

fn parse_event(bytes: &[u8]) -> Option<mapper::IcmpEvent> {
    if bytes.len() < core::mem::size_of::<mapper::IcmpEvent>() {
        tracing::warn!(
            got  = bytes.len(),
            want = core::mem::size_of::<mapper::IcmpEvent>(),
            "ring buffer entry too small — possible ABI mismatch"
        );
        return None;
    }
    // Safety: IcmpEvent is #[repr(C)] with only plain integer fields.
    // read_unaligned avoids any potential unaligned-read UB even if the
    // ring buffer pointer does not satisfy IcmpEvent's alignment.
    Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const mapper::IcmpEvent) })
}

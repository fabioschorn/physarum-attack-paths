// eBPF stimulus module — Linux only.
//
// Attaches physarum_observer to tracepoint/sock/inet_sock_set_state and emits
// the source IP of every inbound TCP connection from the 10.60/16 maze subnet.
// The returned Receiver feeds the 5th arm of the agent's tokio::select! loop.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

/// Raw TCP event written into the EVENTS ring buffer by the eBPF program.
/// Must match `TcpEvent` in physarum-ebpf-observer-ebpf/src/main.rs exactly.
/// ABI: 4+4+2+2+4+16+1+3 = 36 bytes, #[repr(C)].
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpEvent {
    src_addr:   [u8; 4],
    dst_addr:   [u8; 4],
    src_port:   u16,
    dst_port:   u16,
    pid:        u32,
    comm:       [u8; 16],
    event_type: u8,
    _pad:       [u8; 3],
}

/// event_type == 1: inbound TCP accept — a remote peer connected to us.
const EVT_ACCEPT: u8 = 1;

/// Only 10.60.x.x addresses belong to the maze subnet.
const MAZE_OCT0: u8 = 10;
const MAZE_OCT1: u8 = 60;

/// Load the eBPF bytecode from `bytecode_path`, attach the `physarum_observer`
/// program to `tracepoint/sock/inet_sock_set_state`, and return a channel that
/// delivers the source IP of each new inbound TCP connection arriving from the
/// 10.60/16 maze subnet.
///
/// The eBPF program remains loaded for the lifetime of the returned Receiver.
pub fn start(bytecode_path: &Path) -> Result<mpsc::Receiver<Ipv4Addr>> {
    let bytecode = std::fs::read(bytecode_path)
        .with_context(|| format!("read eBPF bytecode: {}", bytecode_path.display()))?;

    let mut bpf = Ebpf::load(&bytecode)?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        tracing::warn!("eBPF kernel logger unavailable: {e}");
    }

    let program: &mut TracePoint = bpf
        .program_mut("physarum_observer")
        .context("eBPF program 'physarum_observer' not found in bytecode")?
        .try_into()
        .context("expected a TracePoint program")?;

    program.load().context("load eBPF program")?;
    program
        .attach("sock", "inet_sock_set_state")
        .context("attach to sock/inet_sock_set_state")?;

    tracing::info!(
        path = %bytecode_path.display(),
        "eBPF stimulus attached to tracepoint/sock/inet_sock_set_state"
    );

    let ring_map = bpf
        .take_map("EVENTS")
        .context("ring buffer map 'EVENTS' not found in bytecode")?;
    let ring_buf = RingBuf::try_from(ring_map)?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    let (tx, rx) = mpsc::channel::<Ipv4Addr>(256);

    tokio::spawn(async move {
        let _bpf = bpf; // keep the program loaded for the lifetime of this task
        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!(err = %e, "eBPF ring buffer poll error");
                    break;
                }
            };
            let rb = guard.get_inner_mut();
            while let Some(bytes) = rb.next() {
                if bytes.len() < core::mem::size_of::<TcpEvent>() {
                    continue;
                }
                // Safety: TcpEvent is #[repr(C)] with plain integer fields;
                // the eBPF program writes exactly this layout into the ring buffer.
                // read_unaligned handles any alignment gap the ring buffer may have.
                let event: TcpEvent =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const TcpEvent) };

                if event.event_type != EVT_ACCEPT {
                    continue;
                }

                let src = Ipv4Addr::from(event.src_addr);
                let oct = src.octets();
                if oct[0] != MAZE_OCT0 || oct[1] != MAZE_OCT1 {
                    continue;
                }

                if tx.send(src).await.is_err() {
                    return; // receiver dropped — agent shutting down
                }
            }
            guard.clear_ready();
        }
    });

    Ok(rx)
}

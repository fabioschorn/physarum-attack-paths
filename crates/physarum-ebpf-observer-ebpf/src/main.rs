#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

// ── kernel constants ─────────────────────────────────────────────────────────

const AF_INET: u16 = 2;
const IPPROTO_TCP: u16 = 6;

// TCP state machine values from include/net/tcp_states.h
const TCP_ESTABLISHED: i32 = 1;
const TCP_CLOSE: i32 = 7;
const TCP_SYN_SENT: i32 = 2; // client sent SYN — becomes ESTABLISHED on outbound connect
const TCP_SYN_RECV: i32 = 3; // server received SYN — becomes ESTABLISHED on inbound accept

// Event type codes (must match mapper.rs in physarum-ebpf-observer)
const EVT_CONNECT: u8 = 0; // connect_established (outbound)
const EVT_ACCEPT: u8 = 1; // accept_established  (inbound)
const EVT_CLOSE: u8 = 2; // close

// ── tracepoint field offsets for sock/inet_sock_set_state ────────────────────
//
// Expected layout — must be validated against:
//   /sys/kernel/tracing/events/sock/inet_sock_set_state/format
// on the target kernel before Gate J is marked GREEN.
// The first 8 bytes are the common header
// (common_type u16 + common_flags u8 + common_preempt_count u8 + common_pid i32).
//
//   offset  8 : skaddr    (8 bytes — socket pointer, ignored)
//   offset 16 : oldstate  (4 bytes — i32)
//   offset 20 : newstate  (4 bytes — i32)
//   offset 24 : sport     (2 bytes — u16, host byte order)
//   offset 26 : dport     (2 bytes — u16, host byte order)
//   offset 28 : family    (2 bytes — u16)
//   offset 30 : protocol  (2 bytes — u16)
//   offset 32 : saddr     (4 bytes — IPv4 source, network byte order)
//   offset 36 : daddr     (4 bytes — IPv4 destination, network byte order)

const OFF_OLDSTATE: usize = 16;
const OFF_NEWSTATE: usize = 20;
const OFF_SPORT: usize = 24;
const OFF_DPORT: usize = 26;
const OFF_FAMILY: usize = 28;
const OFF_PROTOCOL: usize = 30;
const OFF_SADDR: usize = 32;
const OFF_DADDR: usize = 36;

// ── shared event layout (must match TcpEvent in mapper.rs) ───────────────────

#[repr(C)]
struct TcpEvent {
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    pid: u32,
    comm: [u8; 16],
    event_type: u8,
    _pad: [u8; 3],
}

// 256 KiB ring buffer — sufficient for lab-scale TCP flows.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ── tracepoint handler ────────────────────────────────────────────────────────

#[tracepoint]
pub fn physarum_observer(ctx: TracePointContext) -> i32 {
    match handle(&ctx) {
        Ok(_) => 0,
        Err(_) => 0, // always return 0: errors must not interrupt normal execution
    }
}

#[inline(always)]
fn handle(ctx: &TracePointContext) -> Result<(), i64> {
    // Fast-path: skip non-IPv4 and non-TCP sockets before reading more fields.
    let family: u16 = unsafe { ctx.read_at(OFF_FAMILY)? };
    if family != AF_INET {
        return Ok(());
    }
    let protocol: u16 = unsafe { ctx.read_at(OFF_PROTOCOL)? };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }

    let oldstate: i32 = unsafe { ctx.read_at(OFF_OLDSTATE)? };
    let newstate: i32 = unsafe { ctx.read_at(OFF_NEWSTATE)? };

    let event_type = match newstate {
        TCP_ESTABLISHED if oldstate == TCP_SYN_SENT => EVT_CONNECT,
        TCP_ESTABLISHED if oldstate == TCP_SYN_RECV => EVT_ACCEPT,
        TCP_CLOSE => EVT_CLOSE,
        _ => return Ok(()),
    };

    let sport: u16 = unsafe { ctx.read_at(OFF_SPORT)? };
    let dport: u16 = unsafe { ctx.read_at(OFF_DPORT)? };
    let saddr: [u8; 4] = unsafe { ctx.read_at(OFF_SADDR)? };
    let daddr: [u8; 4] = unsafe { ctx.read_at(OFF_DADDR)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = TcpEvent {
        src_addr: saddr,
        dst_addr: daddr,
        src_port: sport,
        dst_port: dport,
        pid,
        comm,
        event_type,
        _pad: [0u8; 3],
    };

    if let Some(mut entry) = EVENTS.reserve::<TcpEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(())
}

// ── required no_std panic handler ────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF verifier rejects loops, so unreachable_unchecked is the standard approach.
    unsafe { core::hint::unreachable_unchecked() }
}

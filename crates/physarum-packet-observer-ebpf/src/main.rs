#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};

// ── Return codes for tc classifiers ──────────────────────────────────────────
//
// TC_ACT_PIPE (3): pass packet to next classifier in chain.
// We never drop packets — this program is a passive observer only.
const TC_ACT_PIPE: i32 = 3;

// ── EtherType ─────────────────────────────────────────────────────────────────
const ETH_P_IP: u16 = 0x0800;

// ── IP protocol numbers ───────────────────────────────────────────────────────
const IPPROTO_ICMP: u8 = 1;

// ── ICMP type codes ───────────────────────────────────────────────────────────
const ICMP_ECHO_REQUEST: u8 = 8;

// ── Ethernet header layout ────────────────────────────────────────────────────
//   dst_mac[6] + src_mac[6] + ethertype[2]
const OFF_ETHERTYPE: usize = 12;
const ETH_HLEN: usize = 14;

// ── IP header offsets (from start of IP header, i.e. ETH_HLEN + offset) ──────
//
// Gate L.3 lab assumption: fixed 20-byte IPv4 header (IHL = 5, no options).
// AWS VPC / AL2023 ICMP echo traffic does not use IP options in practice.
// Future hardening: parse IHL = (first_byte & 0x0f) * 4 before indexing.
const IP_OFF_PROTO: usize = 9;
const IP_OFF_SADDR: usize = 12;
const IP_OFF_DADDR: usize = 16;
const IP_HLEN: usize = 20;

// ── ICMP header offsets (from start of ICMP header = ETH_HLEN + IP_HLEN) ─────
const ICMP_OFF_TYPE: usize = 0;
const ICMP_OFF_CODE: usize = 1;

// ── Shared event layout (must match IcmpEvent in mapper.rs in the userspace crate) ──
//
// IcmpEvent: 4 + 4 + 1 + 1 + 2 = 12 bytes.
// The interface name is not carried in the event; the userspace loader knows
// which interface it attached to and stamps PacketObservation.interface_name.

#[repr(C)]
pub struct IcmpEvent {
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub _pad: [u8; 2],
}

// 256 KiB ring buffer — same capacity as the TCP observer.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ── tc ingress classifier ─────────────────────────────────────────────────────

#[classifier]
pub fn physarum_icmp_observer(ctx: TcContext) -> i32 {
    // Always pass the packet through — errors must not drop traffic.
    match handle(&ctx) {
        Ok(_) | Err(_) => TC_ACT_PIPE,
    }
}

#[inline(always)]
fn handle(ctx: &TcContext) -> Result<(), i64> {
    // ── 1. Check EtherType == IPv4 ───────────────────────────────────────────
    //
    // `ctx.load::<u16>` reads two bytes in network byte order (big-endian).
    // On the little-endian bpfel target we must call `u16::from_be` to
    // compare against the host-order constant ETH_P_IP.
    let ethertype: u16 = unsafe { ctx.load(OFF_ETHERTYPE)? };
    if u16::from_be(ethertype) != ETH_P_IP {
        return Ok(());
    }

    // ── 2. Check IP protocol == ICMP ─────────────────────────────────────────
    let proto: u8 = unsafe { ctx.load(ETH_HLEN + IP_OFF_PROTO)? };
    if proto != IPPROTO_ICMP {
        return Ok(());
    }

    // ── 3. Read source and destination IPv4 ──────────────────────────────────
    //
    // Stored in network byte order (big-endian) — correct for Ipv4Addr::from().
    let src_addr: [u8; 4] = unsafe { ctx.load(ETH_HLEN + IP_OFF_SADDR)? };
    let dst_addr: [u8; 4] = unsafe { ctx.load(ETH_HLEN + IP_OFF_DADDR)? };

    // ── 4. Check ICMP type == echo_request (8) ────────────────────────────────
    let icmp_base = ETH_HLEN + IP_HLEN;
    let icmp_type: u8 = unsafe { ctx.load(icmp_base + ICMP_OFF_TYPE)? };
    if icmp_type != ICMP_ECHO_REQUEST {
        return Ok(());
    }

    let icmp_code: u8 = unsafe { ctx.load(icmp_base + ICMP_OFF_CODE)? };

    // ── 5. Emit event to ring buffer ──────────────────────────────────────────
    let event = IcmpEvent {
        src_addr,
        dst_addr,
        icmp_type,
        icmp_code,
        _pad: [0u8; 2],
    };

    if let Some(mut entry) = EVENTS.reserve::<IcmpEvent>(0) {
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

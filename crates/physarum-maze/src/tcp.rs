/// Raw TCP socket capture — TCP SYN to port 22 as stimulus.
///
/// Mirrors icmp.rs: raw IPPROTO_TCP socket captures incoming SYN packets
/// destined for port 22 and forwards the source IP over a channel.
///
/// Used in PF-2: host X connects to A.1:22 (empty TCP SYN) to signal its
/// presence.  A.1's organism captures the SYN and treats X as a new candidate.
///
/// Requires CAP_NET_RAW (or root).
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

pub fn start(interface: String) -> mpsc::Receiver<Ipv4Addr> {
    let (tx, rx) = mpsc::channel(64);

    std::thread::spawn(move || {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
        if sock < 0 {
            tracing::error!(
                error = %std::io::Error::last_os_error(),
                "raw TCP socket open failed — CAP_NET_RAW required"
            );
            return;
        }

        #[cfg(target_os = "linux")]
        {
            let iface_c = match std::ffi::CString::new(interface.as_str()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(%e, "invalid interface name");
                    unsafe { libc::close(sock) };
                    return;
                }
            };
            let ret = unsafe {
                libc::setsockopt(
                    sock,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_c.as_ptr() as *const libc::c_void,
                    iface_c.as_bytes_with_nul().len() as libc::socklen_t,
                )
            };
            if ret < 0 {
                tracing::warn!(
                    error = %std::io::Error::last_os_error(),
                    iface = %interface,
                    "SO_BINDTODEVICE failed — capturing on all interfaces (non-fatal)"
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        tracing::warn!(
            iface = %interface,
            "SO_BINDTODEVICE not available on this platform — capturing on all interfaces"
        );

        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        tracing::info!(iface = %interface, "TCP raw socket listening for SYN to port 22");

        let mut buf = [0u8; 1500];
        loop {
            let n =
                unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut
                {
                    if tx.is_closed() {
                        break;
                    }
                    continue;
                }
                tracing::error!(%err, "recv error");
                continue;
            }

            if let Some(src) = parse_tcp_syn_port22(&buf[..n as usize]) {
                if tx.blocking_send(src).is_err() {
                    break;
                }
            }
        }

        unsafe { libc::close(sock) };
    });

    rx
}

/// Parse a raw IP+TCP packet; return the source IP only for TCP SYN (no ACK)
/// packets destined for port 22.
fn parse_tcp_syn_port22(bytes: &[u8]) -> Option<Ipv4Addr> {
    // Minimum: 20 bytes IP header + 20 bytes TCP header = 40 bytes
    if bytes.len() < 40 {
        return None;
    }
    let ip_hdr_len = (bytes[0] & 0x0F) as usize * 4;
    if bytes.len() < ip_hdr_len + 20 {
        return None;
    }
    let protocol = bytes[9];
    if protocol != 6 {
        return None; // not TCP
    }
    let dst_port = u16::from_be_bytes([bytes[ip_hdr_len + 2], bytes[ip_hdr_len + 3]]);
    if dst_port != 22 {
        return None;
    }
    // TCP flags are at offset 13 from the TCP header start.
    // SYN=0x02, ACK=0x10.  Accept SYN-only (no ACK) to avoid SYN-ACK noise.
    let flags = bytes[ip_hdr_len + 13];
    if flags & 0x12 != 0x02 {
        return None;
    }
    Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

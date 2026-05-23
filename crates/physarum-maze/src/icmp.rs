/// Raw ICMP socket capture — source IP discovery stimulus.
///
/// Requires CAP_NET_RAW (or root).  Runs in a dedicated blocking thread
/// and forwards source IPs of incoming echo requests over a channel.
///
/// Higher-layer hosts ping lower-layer hosts continuously (systemd timers).
/// Each host's organism captures those *incoming* echo requests and treats
/// the source IP as a "there is a host here — explore it" signal.
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

pub fn start(interface: String) -> mpsc::Receiver<Ipv4Addr> {
    let (tx, rx) = mpsc::channel(64);

    std::thread::spawn(move || {
        let sock = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
        };
        if sock < 0 {
            tracing::error!(
                error = %std::io::Error::last_os_error(),
                "raw ICMP socket open failed — is CAP_NET_RAW set? (sudo ./physarum-maze)"
            );
            return;
        }

        // SO_BINDTODEVICE is Linux-only — bind to the maze subnet NIC.
        // Skipped on non-Linux builds (dev/CI on macOS); on target Linux hosts it is set.
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
        tracing::warn!(iface = %interface, "SO_BINDTODEVICE not available on this platform — capturing on all interfaces");

        // 5-second recv timeout so the thread can detect channel closure.
        let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        tracing::info!(iface = %interface, "ICMP raw socket listening for echo requests");

        let mut buf = [0u8; 1500];
        loop {
            let n = unsafe {
                libc::recv(
                    sock,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };

            if n < 0 {
                let err = std::io::Error::last_os_error();
                // EAGAIN / EWOULDBLOCK means the 5s SO_RCVTIMEO fired — check channel.
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut
                {
                    // Channel closed → main loop is done, exit thread.
                    if tx.is_closed() {
                        break;
                    }
                    continue;
                }
                tracing::error!(%err, "recv error");
                continue;
            }

            if let Some(src) = parse_echo_request(&buf[..n as usize]) {
                if tx.blocking_send(src).is_err() {
                    break; // receiver dropped
                }
            }
        }

        unsafe { libc::close(sock) };
    });

    rx
}

/// Parse a raw IP+ICMP packet and return the source IP if it is an
/// ICMP echo request (type 8, code 0).
fn parse_echo_request(bytes: &[u8]) -> Option<Ipv4Addr> {
    // Minimum: 20 bytes IP header + 8 bytes ICMP header
    if bytes.len() < 28 {
        return None;
    }
    // IP header length is encoded in the low nibble of byte 0 (units: 4 bytes)
    let ip_hdr_len = (bytes[0] & 0x0F) as usize * 4;
    if bytes.len() < ip_hdr_len + 4 {
        return None;
    }
    let protocol = bytes[9];
    if protocol != 1 {
        return None; // not ICMP
    }
    let icmp_type = bytes[ip_hdr_len];
    let icmp_code = bytes[ip_hdr_len + 1];
    if icmp_type != 8 || icmp_code != 0 {
        return None; // not echo request
    }
    Some(Ipv4Addr::new(
        bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

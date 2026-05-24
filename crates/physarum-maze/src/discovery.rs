/// Local subnet discovery and targeted host analysis via RustScan.
///
/// Two distinct scan modes matching physarum's two stimulus paths:
///
///   scan_local_subnet — broad /24 sweep, port 22, low-noise (--min-rate 100),
///     with --no-nmap so no external nmap invocation is needed.  Run on startup
///     and every `--discovery-interval-secs` seconds.  Used by Host A to find
///     A.1 in the same front subnet (10.60.10.0/24).
///
///   scan_targeted — fast /32 with nmap passthrough (-sS -sV) for service
///     version detection.  Informational only; propagation is gated on
///     port_22_open() TCP probe, not on this result.
///
/// RustScan v2.4.1 is pre-installed on every maze host via the user-data
/// script (downloaded from GitHub Releases).  Both functions degrade gracefully
/// (warn + empty result) when rustscan is unavailable.
///
/// Required capability: CAP_NET_RAW (already held — agent runs as root).
use std::net::Ipv4Addr;

/// Discover live hosts on the /24 containing `local_ip` that have port 22 open.
/// Returns discovered IPs excluding `local_ip` itself.
///
/// RustScan is invoked with --no-nmap so the result is pure open-port discovery
/// without a follow-up service scan.  Output lines have the form:
///   Open <ip>:22
pub async fn scan_local_subnet(local_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let o = local_ip.octets();
    let subnet = format!("{}.{}.{}.0/24", o[0], o[1], o[2]);
    tracing::debug!(%subnet, "rustscan /24 discovery");

    let out = tokio::process::Command::new("rustscan")
        .args([
            "-a", &subnet,    // CIDR target
            "--range", "22",  // only scan port 22
            "--ulimit", "500", // conservative file-descriptor limit (shared host)
            "--timeout", "3000", // 3 s per host (ms)
            "--no-nmap",      // skip nmap passthrough — we only need open/closed
        ])
        .output()
        .await;

    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            parse_rustscan_open(&text, local_ip)
        }
        Err(e) => {
            tracing::warn!(error = %e, "rustscan unavailable — /24 discovery skipped");
            vec![]
        }
    }
}

/// Targeted scan of a single host: RustScan port 22 discovery + nmap -sS -sV
/// passthrough for service version info.  Runs fire-and-forget; result is
/// informational only (logged at DEBUG level).
pub async fn scan_targeted(target: Ipv4Addr) {
    tracing::debug!(%target, "rustscan /32 targeted scan (-sS -sV)");

    let result = tokio::process::Command::new("rustscan")
        .args([
            "-a", &target.to_string(),
            "--range", "22",
            "--ulimit", "500",
            "--timeout", "3000",
            "--",          // nmap passthrough separator
            "-sS",         // TCP SYN scan (requires CAP_NET_RAW)
            "-sV",         // service version detection
            "--host-timeout", "8s",
        ])
        .output()
        .await;

    match result {
        Ok(o) if o.status.success() => {
            let last = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.contains("22/") || l.starts_with("Host:"))
                .last()
                .unwrap_or("")
                .to_string();
            tracing::debug!(%target, info = %last, "targeted scan complete");
        }
        Ok(o) => {
            tracing::debug!(
                %target,
                stderr = %String::from_utf8_lossy(&o.stderr),
                "targeted scan returned non-zero"
            );
        }
        Err(e) => {
            tracing::debug!(error = %e, "rustscan unavailable for targeted scan");
        }
    }
}

/// Parse RustScan --no-nmap output and return IPs with port 22 open.
///
/// RustScan emits one line per open port in the form:
///   Open <ip>:<port>
fn parse_rustscan_open(output: &str, exclude: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut hosts = Vec::new();
    for line in output.lines() {
        // Match "Open <ip>:22" lines only.
        let Some(rest) = line.strip_prefix("Open ") else {
            continue;
        };
        let Some((ip_str, port_str)) = rest.split_once(':') else {
            continue;
        };
        if port_str.trim() != "22" {
            continue;
        }
        if let Ok(ip) = ip_str.trim().parse::<Ipv4Addr>() {
            if ip != exclude {
                hosts.push(ip);
                tracing::debug!(%ip, "discovery: port 22 open");
            }
        }
    }
    hosts
}

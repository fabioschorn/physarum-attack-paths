use physarum_scanner::{PortList, Scanner, STARTUP_SWEEP_PORTS};
use std::net::{IpAddr, Ipv4Addr};

/// Proactive /24 startup sweep using `StartupLocalDiscovery` profile.
///
/// Scans `STARTUP_SWEEP_PORTS` against every host in the /24 derived from
/// `local_ip` (excluding `local_ip` itself). Returns all IPs that have at
/// least one port open — regardless of whether port 22 is present.
///
/// Called on every `discovery_ticker` tick (default: every 180 s).
/// Results are fed directly into `llm_loop::run` with stimulus `"startup-sensing"`.
pub async fn startup_sweep(local_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let octets = local_ip.octets();
    let candidates: Vec<IpAddr> = (1u8..=254)
        .filter(|&last| last != octets[3])
        .map(|last| IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], last)))
        .collect();

    let ports = PortList::explicit(STARTUP_SWEEP_PORTS.to_vec());
    match Scanner::new(candidates, ports)
        .batch_size(1_000)
        .timeout_ms(1_500)
        .run()
        .await
    {
        Ok(open) => {
            // Deduplicate: multiple open ports on the same host → one entry.
            let mut seen = std::collections::HashSet::new();
            open.into_iter()
                .filter_map(|sa| match sa.ip() {
                    IpAddr::V4(ip) => {
                        if seen.insert(ip) {
                            Some(ip)
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect()
        }
        Err(e) => {
            tracing::warn!(err = %e, "startup sweep failed");
            vec![]
        }
    }
}

/// Scan common ports on a single target for service characterization.
/// Runs in a spawned task — results are logged only, not returned.
pub fn scan_targeted(target: Ipv4Addr) {
    tokio::spawn(async move {
        let ports = PortList::explicit(vec![22, 80, 443, 8080, 8443, 9000, 9001]);
        match Scanner::new(vec![IpAddr::V4(target)], ports)
            .batch_size(50)
            .timeout_ms(2_000)
            .run()
            .await
        {
            Ok(open) => {
                let port_list: Vec<u16> = open.iter().map(|sa| sa.port()).collect();
                tracing::info!(%target, ?port_list, "targeted scan complete");
            }
            Err(e) => tracing::warn!(%target, err = %e, "targeted scan failed"),
        }
    });
}

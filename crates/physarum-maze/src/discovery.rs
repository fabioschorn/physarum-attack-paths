use physarum_scanner::{PortList, Scanner};
use std::net::{IpAddr, Ipv4Addr};

/// Scan the /24 subnet containing `local_ip` for hosts with port 22 open.
/// Returns all responsive IPs except `local_ip` itself.
pub async fn scan_local_subnet(local_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let octets = local_ip.octets();
    let candidates: Vec<IpAddr> = (1u8..=254)
        .filter(|&last| last != octets[3])
        .map(|last| IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], last)))
        .collect();

    let ports = PortList::explicit(vec![22]);
    match Scanner::new(candidates, ports)
        .batch_size(500)
        .timeout_ms(3_000)
        .run()
        .await
    {
        Ok(open) => open
            .into_iter()
            .filter_map(|sa| match sa.ip() {
                IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect(),
        Err(e) => {
            tracing::warn!(err = %e, "subnet discovery scan failed");
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

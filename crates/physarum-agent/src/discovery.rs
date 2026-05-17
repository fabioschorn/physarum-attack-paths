use chrono::{DateTime, Utc};
use if_addrs::{get_if_addrs, IfAddr};
use physarum_protocol::{
    CandidateDiscoveryReport, CandidateEndpoint, CandidateStatus, DiscoveryScope, DiscoveryTrigger,
    FlowDirection, FlowEvent, FlowObservation,
};
use physarum_scanner::{PortList, Scanner};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── Trait ────────────────────────────────────────────────────────────────────

pub trait CandidateDiscovery: Send + Sync {
    fn run<'a>(
        &'a self,
        scope: &'a DiscoveryScope,
        discovering_agent: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<CandidateEndpoint>> + Send + 'a>>;
}

// ── Config ───────────────────────────────────────────────────────────────────

pub struct DiscoveryConfig {
    pub cidrs: Vec<String>,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
    pub max_candidates: usize,
    pub interval_secs: u64,
    pub seed_cooldown_secs: u64,
}

// ── Local-interface CIDR derivation ──────────────────────────────────────────

/// Minimum prefix length when deriving discovery scope from local interfaces.
/// Networks larger than /16 (>65 534 hosts) are skipped even within RFC1918 space.
const MIN_DISCOVERY_PREFIX: u32 = 16;

fn is_link_local(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 169 && o[1] == 254
}

fn netmask_to_prefix(netmask: Ipv4Addr) -> u32 {
    u32::from(netmask).count_ones()
}

fn network_addr(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & u32::from(netmask))
}

/// Returns one RFC1918 CIDR per eligible local interface.
///
/// Excluded: loopback, link-local (169.254/16), non-private ranges, interfaces
/// with a prefix length below `MIN_DISCOVERY_PREFIX` (prevents accidentally
/// deriving a /8 discovery scope from an interface like 10.0.0.10/8).
pub fn derive_local_rfc1918_cidrs() -> Vec<String> {
    let ifaces = match get_if_addrs() {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "failed to enumerate network interfaces");
            return vec![];
        }
    };
    let mut cidrs: Vec<String> = ifaces
        .iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| {
            if let IfAddr::V4(ref v4) = i.addr {
                if is_link_local(v4.ip) {
                    return None;
                }
                let prefix = netmask_to_prefix(v4.netmask);
                if prefix < MIN_DISCOVERY_PREFIX {
                    tracing::warn!(
                        interface = %i.name,
                        prefix,
                        min = MIN_DISCOVERY_PREFIX,
                        "interface network too large for discovery — skipped"
                    );
                    return None;
                }
                let net = network_addr(v4.ip, v4.netmask);
                let cidr = format!("{}/{}", net, prefix);
                if is_rfc1918(&cidr) {
                    Some(cidr)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    cidrs.sort();
    cidrs.dedup();
    cidrs
}

// ── RFC1918 validation ────────────────────────────────────────────────────────

pub fn validate_rfc1918(cidrs: &[String]) -> Result<(), String> {
    if cidrs.is_empty() {
        return Err("at least one CIDR is required for discovery".to_string());
    }
    for cidr in cidrs {
        if !is_rfc1918(cidr) {
            return Err(format!(
                "CIDR {cidr} is not an RFC1918 private address — Internet-facing scan refused"
            ));
        }
    }
    Ok(())
}

fn is_rfc1918(cidr: &str) -> bool {
    let ip_str = cidr.split('/').next().unwrap_or("");
    let addr: IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(_) => false,
    }
}

// ── CIDR host expansion ───────────────────────────────────────────────────────

/// Expands each IPv4 CIDR into its host addresses (excludes network + broadcast).
///
/// Stops early once `max_hosts` addresses have been collected, preventing large
/// allocations when an oversized CIDR (e.g. 10.0.0.0/8) is passed. The cap is
/// checked *during* the inner loop so no more than `max_hosts` entries are ever
/// allocated, regardless of CIDR size.
pub(crate) fn expand_cidrs(cidrs: &[String], max_hosts: usize) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    'outer: for cidr in cidrs {
        let mut parts = cidr.splitn(2, '/');
        let ip_str = parts.next().unwrap_or("");
        let prefix_str = parts.next().unwrap_or("32");
        let base: std::net::Ipv4Addr = match ip_str.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let prefix: u32 = match prefix_str.parse::<u32>() {
            Ok(p) if p <= 32 => p,
            _ => continue,
        };
        let base_u32 = u32::from(base);
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let network = base_u32 & mask;
        let broadcast = network | !mask;
        if prefix == 32 {
            // /32 host route — the host IS the address itself (no network/broadcast split).
            if ips.len() >= max_hosts {
                break 'outer;
            }
            ips.push(IpAddr::V4(std::net::Ipv4Addr::from(base_u32)));
            continue;
        }
        for host in (network + 1)..broadcast {
            if ips.len() >= max_hosts {
                tracing::warn!(
                    cap = max_hosts,
                    "CIDR expansion capped before full allocation — reduce CIDR prefix or raise max_candidates"
                );
                break 'outer;
            }
            ips.push(IpAddr::V4(std::net::Ipv4Addr::from(host)));
        }
    }
    ips.sort_unstable();
    ips.dedup();
    ips
}

// ── DiscoverySeedQueue (Gate L.1) ─────────────────────────────────────────────

/// Cooldown tracker for eBPF-triggered discovery seeds.
///
/// Uses interior mutability (`Mutex`) so it can be shared as `Arc<DiscoverySeedQueue>`
/// across the discovery loop and the eBPF seed loop without requiring `&mut` access.
/// Prevents a single observed IP from triggering repeated scans within the cooldown window.
pub struct DiscoverySeedQueue {
    seen: Mutex<HashMap<IpAddr, Instant>>,
    cooldown: Duration,
}

impl DiscoverySeedQueue {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            cooldown,
        }
    }

    /// Returns `true` and records the scan time if `ip` is outside the cooldown
    /// window; returns `false` and leaves the record unchanged otherwise.
    pub fn should_scan(&self, ip: IpAddr) -> bool {
        let mut map = self.seen.lock().unwrap();
        let now = Instant::now();
        match map.get(&ip) {
            Some(&last) if now.duration_since(last) < self.cooldown => false,
            _ => {
                map.insert(ip, now);
                true
            }
        }
    }
}

// ── RustScanDiscovery ─────────────────────────────────────────────────────────

pub struct RustScanDiscovery;

impl CandidateDiscovery for RustScanDiscovery {
    fn run<'a>(
        &'a self,
        scope: &'a DiscoveryScope,
        discovering_agent: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<CandidateEndpoint>> + Send + 'a>> {
        Box::pin(async move {
            let max_hosts = scope.max_candidates.saturating_mul(10).max(1024);
            let ips = expand_cidrs(&scope.cidrs, max_hosts);
            let ports = PortList::explicit(scope.ports.clone());

            tracing::debug!(
                ips = ips.len(),
                ports = scope.ports.len(),
                "physarum-scanner starting"
            );

            let sockets = match Scanner::new(ips, ports)
                .timeout_ms(scope.timeout_ms)
                .run()
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "scan error");
                    return vec![];
                }
            };

            let now = Utc::now();
            sockets
                .into_iter()
                .take(scope.max_candidates)
                .map(|s| CandidateEndpoint {
                    discovered_by: discovering_agent.to_string(),
                    ip: s.ip(),
                    port: s.port(),
                    protocol: "tcp".to_string(),
                    discovery_method: "physarum-scanner".to_string(),
                    discovered_at: now,
                    status: CandidateStatus::Discovered,
                    confidence: 0.0,
                    trigger: DiscoveryTrigger::Scheduled,
                })
                .collect()
        })
    }
}

// ── NullDiscovery (CI stub) ───────────────────────────────────────────────────

#[allow(dead_code)]
pub struct NullDiscovery;

impl CandidateDiscovery for NullDiscovery {
    fn run<'a>(
        &'a self,
        _scope: &'a DiscoveryScope,
        _discovering_agent: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<CandidateEndpoint>> + Send + 'a>> {
        Box::pin(async move { vec![] })
    }
}

// ── Discovery loop ────────────────────────────────────────────────────────────

/// Runs the scheduled discovery loop.
///
/// `discovered_sockets` is shared with `probe_loop` — after each scan the loop
/// writes all found sockets into it so the probe loop can promote them to active
/// probe targets without probing all registered agents by default.
pub async fn discovery_loop(
    config: Arc<DiscoveryConfig>,
    discovery: Arc<dyn CandidateDiscovery>,
    discovering_agent: String,
    coordinator: String,
    client: Arc<reqwest::Client>,
    discovered_sockets: Arc<Mutex<HashSet<SocketAddr>>>,
) {
    let interval = Duration::from_secs(config.interval_secs);
    // Gate L.1: seed queue will be populated from eBPF /flow-observations events.
    let mut _seed_queue = DiscoverySeedQueue::new(Duration::from_secs(config.seed_cooldown_secs));
    loop {
        let scope = DiscoveryScope {
            cidrs: config.cidrs.clone(),
            ports: config.ports.clone(),
            timeout_ms: config.timeout_ms,
            max_candidates: config.max_candidates,
        };

        tracing::info!(cidrs = ?config.cidrs, "starting scheduled discovery run");
        let candidates = discovery.run(&scope, &discovering_agent).await;
        tracing::info!(count = candidates.len(), "discovery run complete");

        if !candidates.is_empty() {
            // Share discovered sockets with the probe loop before posting the report,
            // so probe_loop can start targeting them in the next probe cycle.
            {
                let mut sockets = discovered_sockets.lock().unwrap();
                for c in &candidates {
                    sockets.insert(SocketAddr::new(c.ip, c.port));
                }
                tracing::info!(
                    total_known = sockets.len(),
                    new = candidates.len(),
                    "discovered sockets updated — probe loop will use these targets"
                );
            }

            let report = CandidateDiscoveryReport {
                discovering_agent: discovering_agent.clone(),
                scope,
                candidates,
                discovered_at: Utc::now(),
            };
            let url = format!("{coordinator}/candidate-discoveries");
            match client.post(&url).json(&report).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("discovery report posted");
                }
                Ok(resp) => {
                    tracing::warn!(status = %resp.status(), "coordinator rejected discovery report");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to post discovery report");
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

// ── CIDR membership check (Gate L.1) ─────────────────────────────────────────

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let v4 = match ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => return false,
    };
    let mut parts = cidr.splitn(2, '/');
    let net_str = parts.next().unwrap_or("");
    let prefix_str = parts.next().unwrap_or("32");
    let net: Ipv4Addr = match net_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let prefix: u32 = match prefix_str.parse::<u32>() {
        Ok(p) if p <= 32 => p,
        _ => return false,
    };
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    (u32::from(v4) & mask) == (u32::from(net) & mask)
}

pub(crate) fn ip_in_any_cidr(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs.iter().any(|c| ip_in_cidr(ip, c))
}

// ── eBPF seed loop (Gate L.1) ─────────────────────────────────────────────────

/// Polls `GET /flow-observations` for outbound `connect_established` events to unknown
/// RFC1918 hosts and runs a bounded exact-host scan for each qualifying cue.
///
/// This implements the Gate L.1 behavioral rule:
/// "When eBPF senses a new host via a real kernel-observed established flow,
///  the organism takes discovery initiative against that exact host."
#[allow(clippy::too_many_arguments)]
pub async fn ebpf_seed_loop(
    config: Arc<DiscoveryConfig>,
    discovery: Arc<dyn CandidateDiscovery>,
    agent_id: String,
    coordinator: String,
    client: Arc<reqwest::Client>,
    seed_queue: Arc<DiscoverySeedQueue>,
    discovered_sockets: Arc<Mutex<HashSet<SocketAddr>>>,
    own_ip: Option<IpAddr>,
) {
    let poll_interval = Duration::from_secs(10);
    // Only react to observations that arrive after the agent starts up.
    let mut cursor: DateTime<Utc> = Utc::now();

    loop {
        tokio::time::sleep(poll_interval).await;

        let url = format!(
            "{coordinator}/flow-observations?agent_id={agent_id}&since={since}",
            since = urlencoding_rfc3339(&cursor),
        );
        let observations: Vec<FlowObservation> = match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to decode flow-observations");
                    continue;
                }
            },
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "flow-observations poll failed");
                continue;
            }
            Err(e) => {
                tracing::debug!(error = %e, "flow-observations unreachable");
                continue;
            }
        };

        let mut latest_ts = cursor;
        for obs in &observations {
            if obs.observed_at > latest_ts {
                latest_ts = obs.observed_at;
            }

            // Gate L.1: outbound connect → seed the destination.
            // Gate L.2: inbound accept  → seed the source (stimulus host).
            let (seed_ip, trigger) = match (obs.event, obs.direction) {
                (FlowEvent::ConnectEstablished, FlowDirection::Outbound) => {
                    match obs.destination_ip.parse::<IpAddr>() {
                        Ok(ip) => (ip, DiscoveryTrigger::EbpfNewOutboundHost),
                        Err(_) => continue,
                    }
                }
                (FlowEvent::AcceptEstablished, FlowDirection::Inbound) => {
                    match obs.source_ip.parse::<IpAddr>() {
                        Ok(ip) => (ip, DiscoveryTrigger::EbpfNewInboundHost),
                        Err(_) => continue,
                    }
                }
                _ => continue,
            };

            // Skip own IP and non-scoped IPs.
            if own_ip == Some(seed_ip) || !ip_in_any_cidr(seed_ip, &config.cidrs) {
                continue;
            }
            let dst_ip = seed_ip;

            // If this host is already in discovered_sockets, skip the scan (no
            // redundant /32 scan needed) but still post an eBPF-triggered
            // candidate report so the server can preserve the stronger trigger
            // provenance via its priority upsert logic.
            {
                let known_for_dst: Vec<SocketAddr> = {
                    let sockets = discovered_sockets.lock().unwrap();
                    sockets
                        .iter()
                        .filter(|s| s.ip() == dst_ip)
                        .copied()
                        .collect()
                };
                if !known_for_dst.is_empty() {
                    // No cooldown gate here: provenance reports are cheap (no scan) and
                    // inbound (priority=3) must be able to override outbound (priority=2)
                    // regardless of which event arrived first.
                    tracing::info!(ip = %dst_ip, "eBPF cue: known host — asserting trigger provenance");
                    let provenance_candidates: Vec<CandidateEndpoint> = known_for_dst
                        .iter()
                        .map(|s| CandidateEndpoint {
                            discovered_by: agent_id.clone(),
                            ip: s.ip(),
                            port: s.port(),
                            protocol: "tcp".to_string(),
                            discovery_method: "physarum-scanner".to_string(),
                            discovered_at: Utc::now(),
                            status: CandidateStatus::Discovered,
                            confidence: 0.0,
                            trigger,
                        })
                        .collect();
                    let provenance_scope = DiscoveryScope {
                        cidrs: vec![format!("{dst_ip}/32")],
                        ports: known_for_dst.iter().map(|s| s.port()).collect(),
                        timeout_ms: config.timeout_ms,
                        max_candidates: config.max_candidates,
                    };
                    let provenance_report = CandidateDiscoveryReport {
                        discovering_agent: agent_id.clone(),
                        scope: provenance_scope,
                        candidates: provenance_candidates,
                        discovered_at: Utc::now(),
                    };
                    let post_url = format!("{coordinator}/candidate-discoveries");
                    match client.post(&post_url).json(&provenance_report).send().await {
                        Ok(_) => {
                            tracing::info!(ip = %dst_ip, "eBPF trigger provenance report posted");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to post eBPF provenance report");
                        }
                    }
                    continue;
                }
            }

            if !seed_queue.should_scan(dst_ip) {
                tracing::debug!(ip = %dst_ip, "eBPF seed cooldown active — skipping");
                continue;
            }

            tracing::info!(ip = %dst_ip, trigger = ?trigger, "eBPF new-host cue: enqueued seed");

            // Exact-host scan against the observed IP only (/32 — one host).
            let seed_scope = DiscoveryScope {
                cidrs: vec![format!("{dst_ip}/32")],
                ports: config.ports.clone(),
                timeout_ms: config.timeout_ms,
                max_candidates: config.max_candidates,
            };
            tracing::info!(
                ip = %dst_ip,
                seed_cidr = %format!("{dst_ip}/32"),
                "eBPF seed scan: starting exact-host scan"
            );

            let mut candidates = discovery.run(&seed_scope, &agent_id).await;
            if candidates.is_empty() {
                tracing::debug!(ip = %dst_ip, "eBPF seed scan: no open ports found");
                continue;
            }

            // Mark all candidates with the correct eBPF trigger (outbound or inbound).
            for c in &mut candidates {
                c.trigger = trigger;
            }

            // Share with probe loop before posting the report.
            {
                let mut sockets = discovered_sockets.lock().unwrap();
                let new_count = candidates
                    .iter()
                    .filter(|c| sockets.insert(SocketAddr::new(c.ip, c.port)))
                    .count();
                if new_count > 0 {
                    tracing::info!(
                        total_known = sockets.len(),
                        new = new_count,
                        "eBPF seed scan: discovered sockets updated — probe loop will use these targets"
                    );
                }
            }

            let report = CandidateDiscoveryReport {
                discovering_agent: agent_id.clone(),
                scope: seed_scope,
                candidates,
                discovered_at: Utc::now(),
            };
            let post_url = format!("{coordinator}/candidate-discoveries");
            match client.post(&post_url).json(&report).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(ip = %dst_ip, "eBPF seed discovery report posted");
                }
                Ok(resp) => {
                    tracing::warn!(status = %resp.status(), "coordinator rejected eBPF seed report");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to post eBPF seed report");
                }
            }
        }

        // Advance cursor past all processed events to avoid re-processing.
        if latest_ts > cursor {
            cursor = latest_ts + chrono::Duration::microseconds(1);
        }
    }
}

/// Percent-encodes a `DateTime<Utc>` as an RFC3339 string for use in URL query params.
fn urlencoding_rfc3339(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339()
        .chars()
        .flat_map(|c| match c {
            ':' => vec!['%', '3', 'A'],
            '+' => vec!['%', '2', 'B'],
            _ => vec![c],
        })
        .collect()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_detected() {
        assert!(is_link_local("169.254.1.1".parse().unwrap()));
        assert!(is_link_local("169.254.0.0".parse().unwrap()));
        assert!(!is_link_local("10.50.20.1".parse().unwrap()));
        assert!(!is_link_local("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn netmask_to_prefix_class_c() {
        assert_eq!(netmask_to_prefix("255.255.255.0".parse().unwrap()), 24);
    }

    #[test]
    fn netmask_to_prefix_class_b() {
        assert_eq!(netmask_to_prefix("255.255.0.0".parse().unwrap()), 16);
    }

    #[test]
    fn network_addr_removes_host_bits() {
        assert_eq!(
            network_addr(
                "10.50.20.10".parse().unwrap(),
                "255.255.255.0".parse().unwrap()
            ),
            "10.50.20.0".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn derive_local_cidrs_does_not_panic() {
        // Content is environment-dependent; just verify the function completes.
        let _ = derive_local_rfc1918_cidrs();
    }

    #[test]
    fn rfc1918_accepts_class_a() {
        assert!(is_rfc1918("10.50.20.0/24"));
        assert!(is_rfc1918("10.0.0.0/8"));
    }

    #[test]
    fn rfc1918_accepts_class_b() {
        assert!(is_rfc1918("172.16.0.0/12"));
        assert!(is_rfc1918("172.31.255.0/24"));
    }

    #[test]
    fn rfc1918_accepts_class_c() {
        assert!(is_rfc1918("192.168.1.0/24"));
    }

    #[test]
    fn rfc1918_rejects_public_and_all_zeros() {
        assert!(!is_rfc1918("8.8.8.0/24"));
        assert!(!is_rfc1918("0.0.0.0/0"));
        assert!(!is_rfc1918("1.2.3.4/32"));
    }

    #[test]
    fn validate_rfc1918_ok() {
        let cidrs = vec!["10.50.20.0/24".to_string(), "10.50.30.0/24".to_string()];
        assert!(validate_rfc1918(&cidrs).is_ok());
    }

    #[test]
    fn validate_rfc1918_rejects_public_cidr() {
        let cidrs = vec!["10.50.20.0/24".to_string(), "8.8.8.0/24".to_string()];
        let err = validate_rfc1918(&cidrs).unwrap_err();
        assert!(err.contains("8.8.8.0/24"));
    }

    #[test]
    fn validate_rfc1918_rejects_empty_list() {
        assert!(validate_rfc1918(&[]).is_err());
    }

    #[test]
    fn cidr_expansion_slash_30_returns_two_hosts() {
        // 10.0.0.0/30 → hosts .1 and .2 (network=.0, broadcast=.3)
        let ips = expand_cidrs(&["10.0.0.0/30".to_string()], usize::MAX);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn cidr_expansion_deduplicates_overlapping_cidrs() {
        let cidrs = vec!["10.0.0.0/30".to_string(), "10.0.0.0/30".to_string()];
        let ips = expand_cidrs(&cidrs, usize::MAX);
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn cidr_expansion_slash_32_returns_single_host() {
        // /32 host route: exactly the specified host (used for eBPF seed exact-host scans)
        let ips = expand_cidrs(&["10.0.0.1/32".to_string()], usize::MAX);
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn cidr_expansion_caps_before_full_allocation() {
        // /24 has 254 hosts; cap at 10 — must stop at exactly 10 without allocating all 254
        let ips = expand_cidrs(&["10.0.0.0/24".to_string()], 10);
        assert_eq!(ips.len(), 10);
    }

    #[test]
    fn seed_queue_allows_first_scan() {
        let q = DiscoverySeedQueue::new(Duration::from_secs(300));
        assert!(q.should_scan("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn seed_queue_blocks_rescan_within_cooldown() {
        let q = DiscoverySeedQueue::new(Duration::from_secs(300));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(q.should_scan(ip));
        assert!(!q.should_scan(ip));
    }

    #[test]
    fn seed_queue_zero_cooldown_always_allows() {
        let q = DiscoverySeedQueue::new(Duration::ZERO);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(q.should_scan(ip));
        assert!(q.should_scan(ip));
    }

    #[test]
    fn seed_queue_independent_ips_dont_share_cooldown() {
        let q = DiscoverySeedQueue::new(Duration::from_secs(300));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(q.should_scan(ip1));
        assert!(!q.should_scan(ip1)); // blocked
        assert!(q.should_scan(ip2)); // different IP — not blocked
    }

    #[test]
    fn ip_in_cidr_class_c() {
        assert!(ip_in_any_cidr(
            "10.50.30.10".parse().unwrap(),
            &["10.50.30.0/24".to_string()]
        ));
        assert!(!ip_in_any_cidr(
            "10.50.40.10".parse().unwrap(),
            &["10.50.30.0/24".to_string()]
        ));
    }

    #[test]
    fn ip_in_cidr_slash_32_exact() {
        assert!(ip_in_any_cidr(
            "10.50.30.10".parse().unwrap(),
            &["10.50.30.10/32".to_string()]
        ));
        assert!(!ip_in_any_cidr(
            "10.50.30.11".parse().unwrap(),
            &["10.50.30.10/32".to_string()]
        ));
    }

    #[test]
    fn ip_in_cidr_multiple_cidrs() {
        let cidrs = vec!["10.50.20.0/24".to_string(), "10.50.30.0/24".to_string()];
        assert!(ip_in_any_cidr("10.50.20.5".parse().unwrap(), &cidrs));
        assert!(ip_in_any_cidr("10.50.30.5".parse().unwrap(), &cidrs));
        assert!(!ip_in_any_cidr("10.50.40.5".parse().unwrap(), &cidrs));
    }

    #[test]
    fn urlencoding_rfc3339_encodes_colons() {
        let dt = DateTime::from_timestamp(0, 0).unwrap();
        let encoded = urlencoding_rfc3339(&dt);
        assert!(
            !encoded.contains(':'),
            "colons must be percent-encoded: {encoded}"
        );
        assert!(encoded.contains("%3A"), "expected %3A in: {encoded}");
    }

    #[tokio::test]
    async fn null_discovery_returns_empty() {
        let scope = DiscoveryScope {
            cidrs: vec!["10.0.0.0/30".to_string()],
            ports: vec![9001],
            timeout_ms: 100,
            max_candidates: 10,
        };
        let result = NullDiscovery.run(&scope, "agent-b").await;
        assert!(result.is_empty());
    }

    // ── ebpf_seed_loop trigger classification ─────────────────────────────────

    fn make_flow_obs(
        event: FlowEvent,
        direction: FlowDirection,
        src_ip: &str,
        dst_ip: &str,
    ) -> FlowObservation {
        FlowObservation {
            agent_id: "agent-a".to_string(),
            observed_at: chrono::Utc::now(),
            source_ip: src_ip.to_string(),
            source_port: 54321,
            destination_ip: dst_ip.to_string(),
            destination_port: 9001,
            protocol: physarum_protocol::FlowProtocol::Tcp,
            direction,
            event,
            pid: 1,
            comm: "test".to_string(),
        }
    }

    // outbound connect → seed from destination_ip with EbpfNewOutboundHost
    #[test]
    fn outbound_connect_yields_outbound_trigger_and_dst_ip() {
        let obs = make_flow_obs(
            FlowEvent::ConnectEstablished,
            FlowDirection::Outbound,
            "10.50.20.10",
            "10.50.20.20",
        );
        let cidrs = vec!["10.50.20.0/24".to_string()];
        let own_ip: IpAddr = "10.50.20.10".parse().unwrap();

        let (seed_ip, trigger) = match (obs.event, obs.direction) {
            (FlowEvent::ConnectEstablished, FlowDirection::Outbound) => (
                obs.destination_ip.parse::<IpAddr>().unwrap(),
                DiscoveryTrigger::EbpfNewOutboundHost,
            ),
            (FlowEvent::AcceptEstablished, FlowDirection::Inbound) => (
                obs.source_ip.parse::<IpAddr>().unwrap(),
                DiscoveryTrigger::EbpfNewInboundHost,
            ),
            _ => panic!("unexpected"),
        };

        assert_eq!(seed_ip, "10.50.20.20".parse::<IpAddr>().unwrap());
        assert_eq!(trigger, DiscoveryTrigger::EbpfNewOutboundHost);
        assert_ne!(Some(seed_ip), Some(own_ip));
        assert!(ip_in_any_cidr(seed_ip, &cidrs));
    }

    // inbound accept → seed from source_ip with EbpfNewInboundHost
    #[test]
    fn inbound_accept_yields_inbound_trigger_and_src_ip() {
        let obs = make_flow_obs(
            FlowEvent::AcceptEstablished,
            FlowDirection::Inbound,
            "10.50.20.20", // stimulus host B
            "10.50.20.10", // A's own IP (destination of inbound connection)
        );
        let cidrs = vec!["10.50.20.0/24".to_string()];
        let own_ip: IpAddr = "10.50.20.10".parse().unwrap();

        let (seed_ip, trigger) = match (obs.event, obs.direction) {
            (FlowEvent::ConnectEstablished, FlowDirection::Outbound) => (
                obs.destination_ip.parse::<IpAddr>().unwrap(),
                DiscoveryTrigger::EbpfNewOutboundHost,
            ),
            (FlowEvent::AcceptEstablished, FlowDirection::Inbound) => (
                obs.source_ip.parse::<IpAddr>().unwrap(),
                DiscoveryTrigger::EbpfNewInboundHost,
            ),
            _ => panic!("unexpected"),
        };

        assert_eq!(seed_ip, "10.50.20.20".parse::<IpAddr>().unwrap());
        assert_eq!(trigger, DiscoveryTrigger::EbpfNewInboundHost);
        assert_ne!(Some(seed_ip), Some(own_ip));
        assert!(ip_in_any_cidr(seed_ip, &cidrs));
    }

    // non-qualifying events are skipped (Close, unknown direction)
    #[test]
    fn close_event_does_not_qualify() {
        let obs = make_flow_obs(
            FlowEvent::Close,
            FlowDirection::Outbound,
            "10.50.20.10",
            "10.50.20.20",
        );
        let qualified = matches!(
            (obs.event, obs.direction),
            (FlowEvent::ConnectEstablished, FlowDirection::Outbound)
                | (FlowEvent::AcceptEstablished, FlowDirection::Inbound)
        );
        assert!(!qualified, "Close event must not qualify as a seed cue");
    }

    // inbound from out-of-scope IP must be skipped by ip_in_any_cidr guard
    #[test]
    fn inbound_accept_out_of_scope_skipped() {
        let obs = make_flow_obs(
            FlowEvent::AcceptEstablished,
            FlowDirection::Inbound,
            "192.168.99.1", // different subnet — out of scope
            "10.50.20.10",
        );
        let cidrs = vec!["10.50.20.0/24".to_string()];
        let seed_ip: IpAddr = obs.source_ip.parse().unwrap();
        assert!(
            !ip_in_any_cidr(seed_ip, &cidrs),
            "out-of-scope inbound must be rejected"
        );
    }
}

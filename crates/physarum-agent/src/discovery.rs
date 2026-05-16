use chrono::Utc;
use if_addrs::{get_if_addrs, IfAddr};
use physarum_protocol::{
    CandidateDiscoveryReport, CandidateEndpoint, CandidateStatus, DiscoveryScope, DiscoveryTrigger,
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
pub(crate) fn expand_cidrs(cidrs: &[String]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for cidr in cidrs {
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
        for host in (network + 1)..broadcast {
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
/// Prevents a single observed IP from triggering repeated scans within the
/// configured cooldown window. Ready to be populated from `/flow-observations`
/// polling when Gate L.1 eBPF integration lands.
#[allow(dead_code)]
pub struct DiscoverySeedQueue {
    seen: HashMap<IpAddr, Instant>,
    cooldown: Duration,
}

impl DiscoverySeedQueue {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            cooldown,
        }
    }

    /// Returns `true` and records the scan time if `ip` is outside the cooldown
    /// window; returns `false` and leaves the record unchanged otherwise.
    #[allow(dead_code)]
    pub fn should_scan(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        match self.seen.get(&ip) {
            Some(&last) if now.duration_since(last) < self.cooldown => false,
            _ => {
                self.seen.insert(ip, now);
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
            let ips = {
                let mut all = expand_cidrs(&scope.cidrs);
                if all.len() > max_hosts {
                    tracing::warn!(
                        expanded = all.len(),
                        cap = max_hosts,
                        "CIDR expansion capped — reduce discovery CIDRs or raise max_candidates"
                    );
                    all.truncate(max_hosts);
                }
                all
            };
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
        let ips = expand_cidrs(&["10.0.0.0/30".to_string()]);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn cidr_expansion_deduplicates_overlapping_cidrs() {
        let cidrs = vec!["10.0.0.0/30".to_string(), "10.0.0.0/30".to_string()];
        let ips = expand_cidrs(&cidrs);
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn cidr_expansion_slash_32_returns_empty() {
        // /32 host route: network == broadcast, no hosts in range
        let ips = expand_cidrs(&["10.0.0.1/32".to_string()]);
        assert!(ips.is_empty());
    }

    #[test]
    fn seed_queue_allows_first_scan() {
        let mut q = DiscoverySeedQueue::new(Duration::from_secs(300));
        assert!(q.should_scan("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn seed_queue_blocks_rescan_within_cooldown() {
        let mut q = DiscoverySeedQueue::new(Duration::from_secs(300));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(q.should_scan(ip));
        assert!(!q.should_scan(ip));
    }

    #[test]
    fn seed_queue_zero_cooldown_always_allows() {
        let mut q = DiscoverySeedQueue::new(Duration::ZERO);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(q.should_scan(ip));
        assert!(q.should_scan(ip));
    }

    #[test]
    fn seed_queue_independent_ips_dont_share_cooldown() {
        let mut q = DiscoverySeedQueue::new(Duration::from_secs(300));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(q.should_scan(ip1));
        assert!(!q.should_scan(ip1)); // blocked
        assert!(q.should_scan(ip2)); // different IP — not blocked
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
}

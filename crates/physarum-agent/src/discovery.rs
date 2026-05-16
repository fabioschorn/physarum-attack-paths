use chrono::Utc;
use physarum_protocol::{
    CandidateDiscoveryReport, CandidateEndpoint, CandidateStatus, DiscoveryScope, DiscoveryTrigger,
};
use physarum_scanner::{PortList, Scanner};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
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
            let ips = expand_cidrs(&scope.cidrs);
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

pub async fn discovery_loop(
    config: Arc<DiscoveryConfig>,
    discovery: Arc<dyn CandidateDiscovery>,
    discovering_agent: String,
    coordinator: String,
    client: Arc<reqwest::Client>,
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

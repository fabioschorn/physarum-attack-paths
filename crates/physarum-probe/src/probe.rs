use anyhow::Result;
use axum::{routing::get, Json, Router};
use chrono::Utc;
use clap::ValueEnum;
use physarum_protocol::{PeerInfo, ProbeReport, RegisterRequest};
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::discovery::{
    CandidateDiscovery, DiscoveryConfig, DiscoverySeedQueue, RustScanDiscovery,
};

/// Controls how the discovery CIDR scope is built.
#[derive(Debug, Clone, ValueEnum, Default)]
pub enum DiscoveryScopeMode {
    /// Use only --discovery-cidrs. Current default behavior.
    #[default]
    Explicit,
    /// Derive discovery CIDRs from non-loopback local network interfaces (RFC1918 only).
    LocalInterfaces,
    /// Union of --discovery-cidrs and locally-derived interface CIDRs.
    Merged,
}

/// All configuration required to run a probe capability instance.
pub struct ProbeConfig {
    pub id: String,
    pub coordinator: String,
    pub listen: SocketAddr,
    pub advertise_address: String,
    pub probe_interval_seconds: u64,
    pub synthetic_failure_rate: f64,
    pub probe_targets: String,
    pub discovery_enabled: bool,
    pub discovery_cidrs: String,
    pub discovery_ports: String,
    pub discovery_interval_secs: u64,
    pub discovery_max_candidates: usize,
    pub discovery_timeout_ms: u64,
    pub discovery_seed_cooldown_secs: u64,
    pub discovery_scope_mode: DiscoveryScopeMode,
    pub sense_tcp_socket_state: bool,
    pub sense_icmp_packet: bool,
}

/// Maximum number of probe samples kept per peer (sliding window).
const WINDOW_SIZE: usize = 20;

struct ProbeSample {
    success: bool,
    rtt_ms: Option<u64>,
}

/// Short-term sliding-window sensory state for a single peer.
///
/// Keeps the last WINDOW_SIZE probe outcomes. Old samples are evicted as new
/// ones arrive so that statistics always reflect recent conditions, not
/// lifetime aggregates.
pub struct PeerObservation {
    samples: VecDeque<ProbeSample>,
    window_start: Instant,
}

impl PeerObservation {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            window_start: Instant::now(),
        }
    }

    pub fn record(&mut self, success: bool, rtt_ms: Option<u64>) {
        if self.samples.len() >= WINDOW_SIZE {
            self.samples.pop_front();
        }
        self.samples.push_back(ProbeSample { success, rtt_ms });
    }

    pub fn success_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let successes = self.samples.iter().filter(|s| s.success).count();
        successes as f64 / self.samples.len() as f64
    }

    pub fn avg_rtt_ms(&self) -> f64 {
        let rtts: Vec<f64> = self
            .samples
            .iter()
            .filter_map(|s| {
                if s.success {
                    s.rtt_ms.map(|r| r as f64)
                } else {
                    None
                }
            })
            .collect();
        if rtts.is_empty() {
            return 0.0;
        }
        rtts.iter().sum::<f64>() / rtts.len() as f64
    }

    /// Mean absolute deviation of successful RTT samples. Returns 0.0 with fewer than 2.
    pub fn jitter_ms(&self) -> f64 {
        let rtts: Vec<f64> = self
            .samples
            .iter()
            .filter_map(|s| {
                if s.success {
                    s.rtt_ms.map(|r| r as f64)
                } else {
                    None
                }
            })
            .collect();
        if rtts.len() < 2 {
            return 0.0;
        }
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        rtts.iter().map(|r| (r - avg).abs()).sum::<f64>() / rtts.len() as f64
    }

    pub fn sample_count(&self) -> u32 {
        self.samples.len() as u32
    }

    pub fn observation_window_seconds(&self) -> u64 {
        self.window_start.elapsed().as_secs()
    }
}

impl Default for PeerObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(serde::Serialize)]
struct ProbeResponse {
    agent_id: String,
    status: &'static str,
}

pub fn build_probe_router(agent_id: Arc<String>) -> Router {
    Router::new().route(
        "/probe",
        get(move || {
            let id = agent_id.clone();
            async move {
                Json(ProbeResponse {
                    agent_id: id.as_ref().clone(),
                    status: "ok",
                })
            }
        }),
    )
}

pub async fn register(
    id: &str,
    coordinator: &str,
    advertise_address: &str,
    listen_port: u16,
    client: &reqwest::Client,
) -> Result<(), reqwest::Error> {
    let req = RegisterRequest {
        agent_id: id.to_string(),
        address: advertise_address.to_string(),
        probe_port: listen_port,
    };
    client
        .post(format!("{coordinator}/register"))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;
    tracing::info!(agent_id = %id, coordinator = %coordinator, "registered with coordinator");
    Ok(())
}

pub async fn fetch_peers(
    id: &str,
    coordinator: &str,
    client: &reqwest::Client,
) -> Result<Vec<PeerInfo>, reqwest::Error> {
    let peers = client
        .get(format!("{coordinator}/peers/{id}"))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<PeerInfo>>()
        .await?;
    Ok(peers)
}

pub fn build_peer_probe_url(peer: &PeerInfo) -> String {
    format!("http://{}:{}/probe", peer.address, peer.probe_port)
}

pub async fn probe_peer(client: &reqwest::Client, url: &str) -> (bool, Option<u64>) {
    let start = Instant::now();
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let rtt_ms = start.elapsed().as_millis() as u64;
            (true, Some(rtt_ms))
        }
        _ => (false, None),
    }
}

pub fn build_probe_report(
    source: &str,
    peer: &PeerInfo,
    success: bool,
    rtt_ms: Option<u64>,
    obs: &PeerObservation,
) -> ProbeReport {
    ProbeReport {
        source: source.to_string(),
        target: peer.agent_id.clone(),
        success,
        rtt_ms,
        observed_at: Utc::now(),
        success_rate: obs.success_rate(),
        avg_rtt_ms: obs.avg_rtt_ms(),
        jitter_ms: obs.jitter_ms(),
        observation_window_seconds: obs.observation_window_seconds(),
        sample_count: obs.sample_count(),
    }
}

pub async fn send_report(
    coordinator: &str,
    client: &reqwest::Client,
    report: &ProbeReport,
) -> Result<(), reqwest::Error> {
    client
        .post(format!("{coordinator}/report"))
        .json(report)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub fn build_target_filter(probe_targets: &str) -> Vec<String> {
    probe_targets
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub fn parse_ports(ports_str: &str) -> Vec<u16> {
    ports_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u16>().ok())
        .collect()
}

pub fn parse_cidrs(cidrs_str: &str) -> Vec<String> {
    cidrs_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

async fn probe_loop(
    config: Arc<ProbeConfig>,
    client: Arc<reqwest::Client>,
    discovered_sockets: Arc<Mutex<HashSet<SocketAddr>>>,
) {
    let interval = Duration::from_secs(config.probe_interval_seconds);
    let mut observations: HashMap<String, PeerObservation> = HashMap::new();
    let target_filter = build_target_filter(&config.probe_targets);
    // When discovery is enabled and no explicit probe targets were given, the probe
    // loop restricts itself to candidates that the discovery worker has found.
    // Also filter when sense_icmp_packet is active without scheduled sweeps.
    let use_discovery_filter =
        (config.discovery_enabled || config.sense_icmp_packet) && target_filter.is_empty();
    let mut ever_promoted: HashSet<String> = HashSet::new();

    loop {
        match fetch_peers(&config.id, &config.coordinator, &client).await {
            Ok(peers) => {
                let active_peers: Vec<&PeerInfo> = if use_discovery_filter {
                    let sockets = discovered_sockets.lock().unwrap();
                    peers
                        .iter()
                        .filter(|p| {
                            p.address
                                .parse::<IpAddr>()
                                .map(|ip| sockets.contains(&SocketAddr::new(ip, p.probe_port)))
                                .unwrap_or(false)
                        })
                        .collect()
                } else {
                    peers
                        .iter()
                        .filter(|p| target_filter.is_empty() || target_filter.contains(&p.agent_id))
                        .collect()
                };

                if use_discovery_filter {
                    for peer in &active_peers {
                        if ever_promoted.insert(peer.agent_id.clone()) {
                            tracing::info!(
                                agent_id = %peer.agent_id,
                                address = %peer.address,
                                port = peer.probe_port,
                                "candidate promoted to probe target"
                            );
                        }
                    }
                }

                tracing::debug!(count = active_peers.len(), "fetched peers");
                for peer in &active_peers {
                    let url = build_peer_probe_url(peer);
                    let (raw_success, raw_rtt_ms) = probe_peer(&client, &url).await;
                    let (success, rtt_ms) = if config.synthetic_failure_rate > 0.0
                        && rand::thread_rng().gen_bool(config.synthetic_failure_rate)
                    {
                        (false, None)
                    } else {
                        (raw_success, raw_rtt_ms)
                    };
                    let obs = observations.entry(peer.agent_id.clone()).or_default();
                    obs.record(success, rtt_ms);
                    tracing::info!(
                        target = %peer.agent_id,
                        success,
                        rtt_ms = ?rtt_ms,
                        success_rate = obs.success_rate(),
                        "probe result"
                    );
                    let report = build_probe_report(&config.id, peer, success, rtt_ms, obs);
                    if let Err(e) = send_report(&config.coordinator, &client, &report).await {
                        tracing::warn!(error = %e, "failed to send report");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to fetch peers"),
        }
        tokio::time::sleep(interval).await;
    }
}

/// Start the probe capability: bind the probe HTTP server, register with the
/// coordinator, start any configured discovery loops, and run the probe loop.
///
/// Returns only on error — normal operation runs indefinitely.
pub async fn run(config: ProbeConfig) -> Result<()> {
    let config = Arc::new(config);
    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client"),
    );

    let probe_app = build_probe_router(Arc::new(config.id.clone()));
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind probe listener on {}: {e}", config.listen))?;
    tracing::info!(listen = %config.listen, agent_id = %config.id, "probe server listening");

    tokio::spawn(async move {
        axum::serve(listener, probe_app).await.unwrap();
    });

    if let Err(e) = register(
        &config.id,
        &config.coordinator,
        &config.advertise_address,
        config.listen.port(),
        &client,
    )
    .await
    {
        anyhow::bail!("registration failed: {e}");
    }

    let discovered_sockets: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));

    if config.discovery_enabled {
        let explicit_cidrs = parse_cidrs(&config.discovery_cidrs);
        let cidrs = match config.discovery_scope_mode {
            DiscoveryScopeMode::Explicit => explicit_cidrs,
            DiscoveryScopeMode::LocalInterfaces => {
                let derived = crate::discovery::derive_local_rfc1918_cidrs();
                if !derived.is_empty() {
                    tracing::info!(cidrs = ?derived, "discovery scope derived from local interfaces");
                }
                derived
            }
            DiscoveryScopeMode::Merged => {
                let mut merged = crate::discovery::derive_local_rfc1918_cidrs();
                merged.extend(explicit_cidrs);
                merged.sort();
                merged.dedup();
                if !merged.is_empty() {
                    tracing::info!(cidrs = ?merged, "merged explicit + local-interface discovery scope");
                }
                merged
            }
        };
        match crate::discovery::validate_rfc1918(&cidrs) {
            Err(e) => tracing::error!(error = %e, "invalid discovery scope; discovery disabled"),
            Ok(()) => {
                let disc_config = Arc::new(DiscoveryConfig {
                    cidrs,
                    ports: parse_ports(&config.discovery_ports),
                    timeout_ms: config.discovery_timeout_ms,
                    max_candidates: config.discovery_max_candidates,
                    interval_secs: config.discovery_interval_secs,
                    seed_cooldown_secs: config.discovery_seed_cooldown_secs,
                });
                let disc: Arc<dyn CandidateDiscovery> = Arc::new(RustScanDiscovery);
                tracing::info!(
                    cidrs = ?config.discovery_cidrs,
                    interval_secs = config.discovery_interval_secs,
                    "discovery enabled"
                );

                let seed_queue = Arc::new(DiscoverySeedQueue::new(Duration::from_secs(
                    config.discovery_seed_cooldown_secs,
                )));
                let own_ip: Option<IpAddr> = config.advertise_address.parse().ok();

                tokio::spawn(crate::discovery::discovery_loop(
                    disc_config.clone(),
                    disc.clone(),
                    config.id.clone(),
                    config.coordinator.clone(),
                    client.clone(),
                    discovered_sockets.clone(),
                ));

                if config.sense_tcp_socket_state {
                    tokio::spawn(crate::discovery::ebpf_seed_loop(
                        disc_config.clone(),
                        disc.clone(),
                        config.id.clone(),
                        config.coordinator.clone(),
                        client.clone(),
                        seed_queue.clone(),
                        discovered_sockets.clone(),
                        own_ip,
                    ));
                }

                if config.sense_icmp_packet {
                    tokio::spawn(crate::discovery::icmp_seed_loop(
                        disc_config,
                        disc,
                        config.id.clone(),
                        config.coordinator.clone(),
                        client.clone(),
                        seed_queue,
                        discovered_sockets.clone(),
                        own_ip,
                    ));
                }
            }
        }
    } else if config.sense_icmp_packet {
        // ICMP-only mode: no scheduled sweeps, but the ICMP seed loop drives /32 scans.
        let cidrs = crate::discovery::derive_local_rfc1918_cidrs();
        match crate::discovery::validate_rfc1918(&cidrs) {
            Err(e) => {
                tracing::error!(error = %e, "ICMP-only: invalid local-interface scope; ICMP seed loop disabled")
            }
            Ok(()) => {
                let disc_config = Arc::new(DiscoveryConfig {
                    cidrs,
                    ports: parse_ports(&config.discovery_ports),
                    timeout_ms: config.discovery_timeout_ms,
                    max_candidates: config.discovery_max_candidates,
                    interval_secs: config.discovery_interval_secs,
                    seed_cooldown_secs: config.discovery_seed_cooldown_secs,
                });
                let disc: Arc<dyn CandidateDiscovery> = Arc::new(RustScanDiscovery);
                let own_ip: Option<IpAddr> = config.advertise_address.parse().ok();
                let seed_queue = Arc::new(DiscoverySeedQueue::new(Duration::from_secs(
                    config.discovery_seed_cooldown_secs,
                )));
                tracing::info!(
                    "ICMP-only discovery: scheduled sweeps disabled; ICMP seed loop active"
                );
                tokio::spawn(crate::discovery::icmp_seed_loop(
                    disc_config,
                    disc,
                    config.id.clone(),
                    config.coordinator.clone(),
                    client.clone(),
                    seed_queue,
                    discovered_sockets.clone(),
                    own_ip,
                ));
            }
        }
    }

    probe_loop(config, client, discovered_sockets).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_protocol::PeerInfo;

    fn make_peer(agent_id: &str, address: &str, probe_port: u16) -> PeerInfo {
        PeerInfo {
            agent_id: agent_id.to_string(),
            address: address.to_string(),
            probe_port,
        }
    }

    #[test]
    fn register_request_fields() {
        let req = RegisterRequest {
            agent_id: "agent-b".to_string(),
            address: "127.0.0.1".to_string(),
            probe_port: 9001,
        };
        assert_eq!(req.agent_id, "agent-b");
        assert_eq!(req.address, "127.0.0.1");
        assert_eq!(req.probe_port, 9001);
    }

    #[test]
    fn peer_probe_url_format() {
        let peer = make_peer("agent-c", "127.0.0.1", 9002);
        let url = build_peer_probe_url(&peer);
        assert_eq!(url, "http://127.0.0.1:9002/probe");
    }

    #[test]
    fn observation_success_rate_all_success() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(10));
        obs.record(true, Some(12));
        obs.record(true, Some(8));
        assert!((obs.success_rate() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn observation_success_rate_with_failures() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(10));
        obs.record(false, None);
        obs.record(false, None);
        obs.record(true, Some(8));
        assert!((obs.success_rate() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn observation_avg_rtt() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(10));
        obs.record(true, Some(20));
        obs.record(false, None);
        assert!((obs.avg_rtt_ms() - 15.0).abs() < 1e-12);
    }

    #[test]
    fn observation_jitter_zero_with_one_sample() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(10));
        assert_eq!(obs.jitter_ms(), 0.0);
    }

    #[test]
    fn observation_jitter_nonzero_with_spread() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(10));
        obs.record(true, Some(20));
        assert!((obs.jitter_ms() - 5.0).abs() < 1e-12);
    }

    #[test]
    fn observation_sample_count() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(5));
        obs.record(false, None);
        obs.record(false, None);
        assert_eq!(obs.sample_count(), 3);
    }

    #[test]
    fn window_caps_sample_count_at_window_size() {
        let mut obs = PeerObservation::new();
        for i in 0..30u64 {
            obs.record(true, Some(i));
        }
        assert!(obs.sample_count() <= WINDOW_SIZE as u32);
        assert_eq!(obs.sample_count(), WINDOW_SIZE as u32);
    }

    #[test]
    fn window_drops_oldest_samples() {
        let mut obs = PeerObservation::new();
        for _ in 0..WINDOW_SIZE {
            obs.record(true, Some(10));
        }
        obs.record(true, Some(10));
        assert_eq!(obs.sample_count(), WINDOW_SIZE as u32);
        assert!((obs.success_rate() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn window_success_rate_reflects_recent_window_not_lifetime() {
        let mut obs = PeerObservation::new();
        for _ in 0..WINDOW_SIZE {
            obs.record(true, Some(5));
        }
        assert!((obs.success_rate() - 1.0).abs() < 1e-12);
        for _ in 0..WINDOW_SIZE {
            obs.record(false, None);
        }
        assert!(obs.success_rate() < 1e-12);
    }

    #[test]
    fn window_rtt_and_jitter_use_only_successful_samples_in_window() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(100));
        obs.record(true, Some(200));
        obs.record(false, None);
        assert!((obs.avg_rtt_ms() - 150.0).abs() < 1e-12);
        assert!((obs.jitter_ms() - 50.0).abs() < 1e-12);
    }

    #[test]
    fn target_filter_empty_means_no_restriction() {
        let filter = build_target_filter("");
        assert!(filter.is_empty());
    }

    #[test]
    fn target_filter_parses_comma_separated_ids() {
        let filter = build_target_filter("agent-c,agent-e");
        assert_eq!(filter, vec!["agent-c", "agent-e"]);
    }

    #[test]
    fn target_filter_trims_whitespace() {
        let filter = build_target_filter(" agent-c , agent-e ");
        assert_eq!(filter, vec!["agent-c", "agent-e"]);
    }

    #[test]
    fn target_filter_excludes_unlisted_peer() {
        let filter = build_target_filter("agent-c,agent-e");
        let peers = [
            make_peer("agent-c", "127.0.0.1", 9002),
            make_peer("agent-d", "127.0.0.1", 9003),
            make_peer("agent-e", "127.0.0.1", 9004),
        ];
        let active: Vec<&PeerInfo> = peers
            .iter()
            .filter(|p| filter.is_empty() || filter.contains(&p.agent_id))
            .collect();
        let ids: Vec<&str> = active.iter().map(|p| p.agent_id.as_str()).collect();
        assert_eq!(ids, ["agent-c", "agent-e"]);
    }

    #[test]
    fn probe_report_success_includes_observation() {
        let peer = make_peer("agent-c", "127.0.0.1", 9002);
        let mut obs = PeerObservation::new();
        obs.record(true, Some(7));
        let report = build_probe_report("agent-b", &peer, true, Some(7), &obs);
        assert_eq!(report.source, "agent-b");
        assert_eq!(report.target, "agent-c");
        assert!(report.success);
        assert_eq!(report.rtt_ms, Some(7));
        assert!((report.success_rate - 1.0).abs() < 1e-12);
        assert!((report.avg_rtt_ms - 7.0).abs() < 1e-12);
        assert_eq!(report.sample_count, 1);
    }

    #[test]
    fn probe_report_failure_includes_observation() {
        let peer = make_peer("agent-c", "127.0.0.1", 9002);
        let mut obs = PeerObservation::new();
        obs.record(false, None);
        let report = build_probe_report("agent-b", &peer, false, None, &obs);
        assert!(!report.success);
        assert_eq!(report.rtt_ms, None);
        assert!((report.success_rate - 0.0).abs() < 1e-12);
        assert_eq!(report.sample_count, 1);
    }
}

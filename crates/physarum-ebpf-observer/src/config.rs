use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "physarum-ebpf-observer",
    about = "Physarum passive TCP flow observer — captures connection metadata via eBPF",
    version
)]
pub struct Config {
    /// Agent identifier reported with every FlowObservation.
    #[arg(long, env = "PHYSARUM_AGENT_ID")]
    pub agent_id: String,

    /// Coordinator base URL to post flow observations to.
    #[arg(
        long,
        default_value = "http://127.0.0.1:8080",
        env = "PHYSARUM_COORDINATOR_URL"
    )]
    pub coordinator_url: String,

    /// Path to compiled eBPF bytecode (ELF). Required on Linux.
    #[arg(long, env = "PHYSARUM_BPF_BYTECODE")]
    pub bpf_bytecode: Option<PathBuf>,

    /// HTTP request timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub server_timeout_ms: u64,

    /// Only log events to stdout; do not POST to the coordinator.
    #[arg(long)]
    pub dry_run: bool,

    /// Log level passed to the tracing filter (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Only report flows whose destination port matches this value (0 = no filter).
    #[arg(long, default_value_t = 0)]
    pub filter_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let config = Config::try_parse_from(["obs", "--agent-id", "agent-b"]).unwrap();
        assert_eq!(config.coordinator_url, "http://127.0.0.1:8080");
        assert_eq!(config.server_timeout_ms, 5000);
        assert!(!config.dry_run);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.filter_port, 0);
        assert!(config.bpf_bytecode.is_none());
    }

    #[test]
    fn dry_run_flag_is_parsed() {
        let config = Config::try_parse_from(["obs", "--agent-id", "agent-b", "--dry-run"]).unwrap();
        assert!(config.dry_run);
    }

    #[test]
    fn filter_port_is_parsed() {
        let config =
            Config::try_parse_from(["obs", "--agent-id", "agent-b", "--filter-port", "9002"])
                .unwrap();
        assert_eq!(config.filter_port, 9002);
    }
}

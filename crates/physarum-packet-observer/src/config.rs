use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "physarum-packet-observer",
    about = "Physarum passive ICMP packet observer — captures echo_request metadata via eBPF tc ingress",
    version
)]
pub struct Config {
    /// Agent identifier reported with every PacketObservation.
    #[arg(long, env = "PHYSARUM_AGENT_ID")]
    pub agent_id: String,

    /// Coordinator base URL to post packet observations to.
    #[arg(
        long,
        default_value = "http://127.0.0.1:8080",
        env = "PHYSARUM_COORDINATOR_URL"
    )]
    pub coordinator_url: String,

    /// Path to compiled eBPF bytecode ELF. Required on Linux.
    #[arg(long, env = "PHYSARUM_BPF_BYTECODE")]
    pub bpf_bytecode: Option<PathBuf>,

    /// Network interface to attach the tc ingress classifier to.
    #[arg(long, default_value = "eth0", env = "PHYSARUM_INTERFACE")]
    pub interface: String,

    /// HTTP request timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub server_timeout_ms: u64,

    /// Only log events to stdout; do not POST to the coordinator.
    #[arg(long)]
    pub dry_run: bool,

    /// Log level passed to the tracing filter (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let config = Config::try_parse_from(["pkt-obs", "--agent-id", "agent-b"]).unwrap();
        assert_eq!(config.coordinator_url, "http://127.0.0.1:8080");
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.server_timeout_ms, 5000);
        assert!(!config.dry_run);
        assert_eq!(config.log_level, "info");
        assert!(config.bpf_bytecode.is_none());
    }

    #[test]
    fn interface_is_configurable() {
        let config =
            Config::try_parse_from(["pkt-obs", "--agent-id", "a", "--interface", "ens5"]).unwrap();
        assert_eq!(config.interface, "ens5");
    }

    #[test]
    fn dry_run_flag_is_parsed() {
        let config = Config::try_parse_from(["pkt-obs", "--agent-id", "a", "--dry-run"]).unwrap();
        assert!(config.dry_run);
    }
}

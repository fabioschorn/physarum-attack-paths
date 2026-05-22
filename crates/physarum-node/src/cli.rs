use clap::Parser;
use physarum_node_runtime::CapabilitySet;
use physarum_probe::probe::DiscoveryScopeMode;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Clone)]
#[command(
    name = "physarum-node",
    about = "Physarum role-fluid node — composes probe, observer, and discovery capabilities",
    long_about = "physarum-node is a single process that composes physarum capabilities.\n\
                  Use --capabilities to select which roles this node performs.\n\n\
                  Examples:\n  \
                  physarum-node --capabilities probe ...\n  \
                  physarum-node --capabilities probe,observe-flow ...\n  \
                  physarum-node --capabilities probe,observe-flow,observe-packet ..."
)]
pub struct Cli {
    /// Comma-separated capability set.
    /// Valid tokens: probe, observe-flow, observe-packet, discover-rustscan.
    /// The 'probe' capability is required and must always be included.
    #[arg(long, env = "PHYSARUM_CAPABILITIES")]
    pub capabilities: CapabilitySet,

    // ── Probe / agent flags ───────────────────────────────────────────────
    /// Agent identifier reported to the coordinator.
    #[arg(long, env = "PHYSARUM_AGENT_ID")]
    pub id: String,

    /// Coordinator base URL.
    #[arg(long, env = "PHYSARUM_COORDINATOR")]
    pub coordinator: String,

    /// Address this node listens on for inbound probes.
    #[arg(long, env = "PHYSARUM_LISTEN")]
    pub listen: SocketAddr,

    /// Externally reachable address advertised to the coordinator.
    #[arg(long, env = "PHYSARUM_ADVERTISE_ADDRESS")]
    pub advertise_address: String,

    /// Seconds between outbound probe rounds.
    #[arg(long, default_value = "10", env = "PHYSARUM_PROBE_INTERVAL_SECONDS")]
    pub probe_interval_seconds: u64,

    /// Fraction of outgoing probes to report as failed regardless of actual result.
    /// Range [0.0, 1.0]. Lab-only — not a production signal.
    #[arg(long, default_value = "0.0", env = "PHYSARUM_SYNTHETIC_FAILURE_RATE")]
    pub synthetic_failure_rate: f64,

    /// Comma-separated list of agent IDs this node will probe.
    /// Empty means probe all registered peers.
    #[arg(long, default_value = "", env = "PHYSARUM_PROBE_TARGETS")]
    pub probe_targets: String,

    // ── Discovery flags ───────────────────────────────────────────────────
    /// Enable blind TCP candidate discovery (Gate L).
    #[arg(long, default_value_t = false, env = "PHYSARUM_DISCOVERY_ENABLED")]
    pub discovery_enabled: bool,

    /// RFC1918 CIDRs to scan, comma-separated (e.g. "10.50.20.0/24").
    #[arg(long, default_value = "", env = "PHYSARUM_DISCOVERY_CIDRS")]
    pub discovery_cidrs: String,

    /// TCP ports to probe during discovery, comma-separated.
    #[arg(
        long,
        default_value = "9001,9002,9003,9004",
        env = "PHYSARUM_DISCOVERY_PORTS"
    )]
    pub discovery_ports: String,

    /// Seconds between scheduled discovery runs.
    #[arg(long, default_value_t = 300, env = "PHYSARUM_DISCOVERY_INTERVAL_SECS")]
    pub discovery_interval_secs: u64,

    /// Maximum candidates returned per discovery run.
    #[arg(long, default_value_t = 50, env = "PHYSARUM_DISCOVERY_MAX_CANDIDATES")]
    pub discovery_max_candidates: usize,

    /// Connection timeout for each probe socket (ms).
    #[arg(long, default_value_t = 1500, env = "PHYSARUM_DISCOVERY_TIMEOUT_MS")]
    pub discovery_timeout_ms: u64,

    /// Cooldown before re-scanning a seed IP (Gate L.1, seconds).
    #[arg(
        long,
        default_value_t = 300,
        env = "PHYSARUM_DISCOVERY_SEED_COOLDOWN_SECS"
    )]
    pub discovery_seed_cooldown_secs: u64,

    /// How to build the discovery CIDR scope.
    #[arg(
        long,
        default_value = "explicit",
        env = "PHYSARUM_DISCOVERY_SCOPE_MODE"
    )]
    pub discovery_scope_mode: DiscoveryScopeMode,

    /// Enable TCP socket-state sensing via eBPF flow-observations (Gate L.2). Default: true.
    #[arg(long, default_value_t = true, env = "PHYSARUM_SENSE_TCP_SOCKET_STATE")]
    pub sense_tcp_socket_state: bool,

    /// Enable ICMP packet-level sensing via packet-observations (Gate L.3). Default: false.
    #[arg(long, default_value_t = false, env = "PHYSARUM_SENSE_ICMP_PACKET")]
    pub sense_icmp_packet: bool,

    // ── ObserveEbpf (observe-flow) flags ─────────────────────────────────
    /// Path to the compiled eBPF bytecode ELF for TCP flow observation.
    /// Required when --capabilities includes 'observe-flow'.
    #[arg(long, env = "PHYSARUM_FLOW_BPF_BYTECODE")]
    pub flow_bpf_bytecode: Option<PathBuf>,

    /// Only report TCP flows whose destination port matches this value (0 = no filter).
    #[arg(long, default_value_t = 0, env = "PHYSARUM_FLOW_FILTER_PORT")]
    pub flow_filter_port: u16,

    // ── ObservePacket (observe-packet) flags ─────────────────────────────
    /// Path to the compiled eBPF bytecode ELF for ICMP packet observation.
    /// Required when --capabilities includes 'observe-packet'.
    #[arg(long, env = "PHYSARUM_PACKET_BPF_BYTECODE")]
    pub packet_bpf_bytecode: Option<PathBuf>,

    /// Network interface to attach the tc ingress ICMP observer to.
    #[arg(long, default_value = "eth0", env = "PHYSARUM_INTERFACE")]
    pub interface: String,

    // ── Shared ───────────────────────────────────────────────────────────
    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "PHYSARUM_LOG_LEVEL")]
    pub log_level: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_node_runtime::NodeCapability;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("parse failed")
    }

    fn try_parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn base_args() -> Vec<&'static str> {
        vec![
            "physarum-node",
            "--id",
            "agent-b",
            "--coordinator",
            "http://10.50.10.10:8080",
            "--listen",
            "0.0.0.0:9001",
            "--advertise-address",
            "10.50.20.10",
        ]
    }

    #[test]
    fn probe_only_capability_parses() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe"]);
        let cli = parse(&args);
        assert!(cli.capabilities.contains(&NodeCapability::Probe));
        assert!(!cli.capabilities.contains(&NodeCapability::ObserveEbpf));
        assert!(!cli.capabilities.contains(&NodeCapability::ObservePacket));
    }

    #[test]
    fn probe_observe_flow_parses() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe,observe-flow"]);
        let cli = parse(&args);
        assert!(cli.capabilities.contains(&NodeCapability::Probe));
        assert!(cli.capabilities.contains(&NodeCapability::ObserveEbpf));
    }

    #[test]
    fn probe_observe_packet_parses() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe,observe-packet"]);
        let cli = parse(&args);
        assert!(cli.capabilities.contains(&NodeCapability::Probe));
        assert!(cli.capabilities.contains(&NodeCapability::ObservePacket));
    }

    #[test]
    fn all_three_capabilities_parse() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe,observe-flow,observe-packet"]);
        let cli = parse(&args);
        assert!(cli.capabilities.contains(&NodeCapability::Probe));
        assert!(cli.capabilities.contains(&NodeCapability::ObserveEbpf));
        assert!(cli.capabilities.contains(&NodeCapability::ObservePacket));
    }

    #[test]
    fn unknown_capability_is_rejected() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe,teleport"]);
        assert!(try_parse(&args).is_err());
    }

    #[test]
    fn missing_capabilities_flag_is_rejected() {
        assert!(try_parse(&base_args()).is_err());
    }

    #[test]
    fn discovery_flags_default_correctly() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe"]);
        let cli = parse(&args);
        assert!(!cli.discovery_enabled);
        assert_eq!(cli.discovery_cidrs, "");
        assert_eq!(cli.discovery_ports, "9001,9002,9003,9004");
        assert_eq!(cli.discovery_interval_secs, 300);
        assert_eq!(cli.discovery_max_candidates, 50);
        assert_eq!(cli.discovery_timeout_ms, 1500);
        assert_eq!(cli.discovery_seed_cooldown_secs, 300);
        assert!(cli.sense_tcp_socket_state);
        assert!(!cli.sense_icmp_packet);
        assert_eq!(cli.synthetic_failure_rate, 0.0);
        assert_eq!(cli.probe_targets, "");
    }

    #[test]
    fn discovery_enabled_flag_parses() {
        let mut args = base_args();
        args.extend([
            "--capabilities",
            "probe",
            "--discovery-enabled",
            "--discovery-cidrs",
            "10.50.20.0/24",
        ]);
        let cli = parse(&args);
        assert!(cli.discovery_enabled);
        assert_eq!(cli.discovery_cidrs, "10.50.20.0/24");
    }

    #[test]
    fn observer_flags_default_correctly() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe,observe-flow,observe-packet"]);
        let cli = parse(&args);
        assert!(cli.flow_bpf_bytecode.is_none());
        assert!(cli.packet_bpf_bytecode.is_none());
        assert_eq!(cli.interface, "eth0");
        assert_eq!(cli.flow_filter_port, 0);
    }
}

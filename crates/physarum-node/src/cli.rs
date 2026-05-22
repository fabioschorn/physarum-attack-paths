use clap::Parser;
use physarum_node_runtime::CapabilitySet;
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
                  physarum-node --capabilities probe,observe-flow --flow-bpf-bytecode /usr/local/lib/physarum-ebpf-observer-ebpf.elf ...\n  \
                  physarum-node --capabilities probe,observe-packet --packet-bpf-bytecode /usr/local/lib/physarum-packet-observer-ebpf.elf ..."
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
        assert!(!cli.capabilities.contains(&NodeCapability::ObservePacket));
    }

    #[test]
    fn probe_observe_packet_parses() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe,observe-packet"]);
        let cli = parse(&args);
        assert!(cli.capabilities.contains(&NodeCapability::Probe));
        assert!(!cli.capabilities.contains(&NodeCapability::ObserveEbpf));
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
    fn observer_flags_default_correctly() {
        let mut args = base_args();
        args.extend(["--capabilities", "probe,observe-flow,observe-packet"]);
        let cli = parse(&args);
        assert!(cli.flow_bpf_bytecode.is_none());
        assert!(cli.packet_bpf_bytecode.is_none());
        assert_eq!(cli.interface, "eth0");
        assert_eq!(cli.flow_filter_port, 0);
    }

    #[test]
    fn observer_flags_are_configurable() {
        let mut args = base_args();
        args.extend([
            "--capabilities",
            "probe,observe-flow,observe-packet",
            "--flow-bpf-bytecode",
            "/usr/local/lib/flow.elf",
            "--packet-bpf-bytecode",
            "/usr/local/lib/packet.elf",
            "--interface",
            "ens5",
            "--flow-filter-port",
            "9001",
        ]);
        let cli = parse(&args);
        assert_eq!(
            cli.flow_bpf_bytecode.as_deref(),
            Some(std::path::Path::new("/usr/local/lib/flow.elf"))
        );
        assert_eq!(
            cli.packet_bpf_bytecode.as_deref(),
            Some(std::path::Path::new("/usr/local/lib/packet.elf"))
        );
        assert_eq!(cli.interface, "ens5");
        assert_eq!(cli.flow_filter_port, 9001);
    }
}

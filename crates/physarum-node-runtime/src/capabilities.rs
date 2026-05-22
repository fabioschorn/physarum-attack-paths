use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeCapability {
    Probe,
    /// TCP flow observer via eBPF tracepoint (physarum-ebpf-observer).
    ObserveEbpf,
    /// ICMP packet observer via eBPF tc ingress (physarum-packet-observer).
    ObservePacket,
    DiscoverRustScan,
    ServeLocal,
    Coordinate,
}

impl fmt::Display for NodeCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe => write!(f, "probe"),
            Self::ObserveEbpf => write!(f, "observe-flow"),
            Self::ObservePacket => write!(f, "observe-packet"),
            Self::DiscoverRustScan => write!(f, "discover-rustscan"),
            Self::ServeLocal => write!(f, "serve-local"),
            Self::Coordinate => write!(f, "coordinate"),
        }
    }
}

#[derive(Debug, Error)]
#[error("unknown capability: {0:?}")]
pub struct ParseCapabilityError(String);

impl FromStr for NodeCapability {
    type Err = ParseCapabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "probe" => Ok(Self::Probe),
            "observe-flow" => Ok(Self::ObserveEbpf),
            "observe-packet" => Ok(Self::ObservePacket),
            "discover-rustscan" => Ok(Self::DiscoverRustScan),
            "serve-local" => Ok(Self::ServeLocal),
            "coordinate" => Ok(Self::Coordinate),
            other => Err(ParseCapabilityError(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CapabilitySet(pub HashSet<NodeCapability>);

impl CapabilitySet {
    pub fn new(caps: impl IntoIterator<Item = NodeCapability>) -> Self {
        Self(caps.into_iter().collect())
    }

    pub fn contains(&self, cap: &NodeCapability) -> bool {
        self.0.contains(cap)
    }

    pub fn requires_ebpf_privilege(&self) -> bool {
        self.0.contains(&NodeCapability::ObserveEbpf)
    }
}

/// Parse a comma-separated capability list (e.g. "probe,observe-flow").
impl FromStr for CapabilitySet {
    type Err = ParseCapabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let caps = s
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(NodeCapability::from_str)
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self(caps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_capability() {
        assert_eq!(
            "probe".parse::<NodeCapability>().unwrap(),
            NodeCapability::Probe
        );
        assert_eq!(
            "observe-flow".parse::<NodeCapability>().unwrap(),
            NodeCapability::ObserveEbpf
        );
        assert_eq!(
            "observe-packet".parse::<NodeCapability>().unwrap(),
            NodeCapability::ObservePacket
        );
        assert_eq!(
            "discover-rustscan".parse::<NodeCapability>().unwrap(),
            NodeCapability::DiscoverRustScan
        );
    }

    #[test]
    fn parse_unknown_capability_errors() {
        assert!("unknown".parse::<NodeCapability>().is_err());
    }

    #[test]
    fn parse_capability_set_csv() {
        let set: CapabilitySet = "probe,observe-flow".parse().unwrap();
        assert!(set.contains(&NodeCapability::Probe));
        assert!(set.contains(&NodeCapability::ObserveEbpf));
        assert!(!set.contains(&NodeCapability::DiscoverRustScan));
    }

    #[test]
    fn requires_ebpf_privilege() {
        let with_ebpf: CapabilitySet = "probe,observe-flow".parse().unwrap();
        let without_ebpf: CapabilitySet = "probe,discover-rustscan".parse().unwrap();
        assert!(with_ebpf.requires_ebpf_privilege());
        assert!(!without_ebpf.requires_ebpf_privilege());
    }

    #[test]
    fn display_roundtrip() {
        for cap in [
            NodeCapability::Probe,
            NodeCapability::ObserveEbpf,
            NodeCapability::ObservePacket,
            NodeCapability::DiscoverRustScan,
            NodeCapability::ServeLocal,
            NodeCapability::Coordinate,
        ] {
            let s = cap.to_string();
            let parsed: NodeCapability = s.parse().unwrap();
            assert_eq!(cap, parsed);
        }
    }
}

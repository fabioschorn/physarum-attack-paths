use crate::AgentId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// What initiated a discovery run.
///
/// `Startup` and `Scheduled` are Gate L MVP triggers.
/// `EbpfNew*` variants are placeholders for Gate L.1 — they are serialised
/// correctly today so that future reports containing them round-trip without
/// a protocol version bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryTrigger {
    Startup,
    Scheduled,
    /// Gate L.1: eBPF observed a successful outbound TCP connection to an
    /// unknown host inside the configured discovery scope.
    EbpfNewOutboundHost,
    /// Gate L.1: eBPF observed an inbound TCP accept from an unknown host.
    EbpfNewInboundHost,
}

/// Lifecycle state of a discovered candidate endpoint.
///
/// Invariant: a graph edge (`/report`) is only created after `ProbeValidated`.
/// `Discovered` alone never implies a trusted path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// RustScan returned this socket as open; no probe has been attempted yet.
    Discovered,
    /// An active probe from this agent to ip:port succeeded.
    ProbeValidated,
    /// eBPF observer confirmed a TCP flow for the probed socket (Gate L.1).
    FlowConfirmed,
    /// All probe retries failed; endpoint will not become a graph edge.
    Rejected,
}

/// A single endpoint that physarum-scanner found open during a discovery run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateEndpoint {
    pub discovered_by: AgentId,
    pub ip: IpAddr,
    pub port: u16,
    /// Always "tcp" for Gate L (UDP is out of scope).
    pub protocol: String,
    /// "physarum-scanner" — allows future adapters without a schema change.
    pub discovery_method: String,
    pub discovered_at: DateTime<Utc>,
    pub status: CandidateStatus,
    /// Confidence starts at 0.0 (Discovered) and increases with validation.
    /// 0.5 after ProbeValidated; 1.0 after FlowConfirmed (Gate L.1).
    pub confidence: f64,
    pub trigger: DiscoveryTrigger,
}

/// Scope passed to a discovery run — defines what is allowed to be scanned.
///
/// RFC1918 validation is enforced by the agent before any scan begins;
/// this struct carries the effective scope actually used so the server can
/// store it alongside the report for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryScope {
    /// RFC1918 CIDRs, e.g. `["10.50.20.0/24", "10.50.30.0/24"]`.
    pub cidrs: Vec<String>,
    /// Explicit port list, e.g. `[9001, 9002, 9003, 9004]`.
    pub ports: Vec<u16>,
    /// Per-host connection timeout passed to physarum-scanner (ms).
    pub timeout_ms: u64,
    /// Hard cap on returned endpoints — prevents runaway discovery.
    pub max_candidates: usize,
}

/// Sent by an agent to `POST /candidate-discoveries` after a scan completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateDiscoveryReport {
    pub discovering_agent: AgentId,
    /// The scope actually used for this run (post-validation).
    pub scope: DiscoveryScope,
    pub candidates: Vec<CandidateEndpoint>,
    pub discovered_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_endpoint(ip: &str, port: u16) -> CandidateEndpoint {
        CandidateEndpoint {
            discovered_by: "agent-b".to_string(),
            ip: ip.parse().unwrap(),
            port,
            protocol: "tcp".to_string(),
            discovery_method: "physarum-scanner".to_string(),
            discovered_at: Utc::now(),
            status: CandidateStatus::Discovered,
            confidence: 0.0,
            trigger: DiscoveryTrigger::Startup,
        }
    }

    #[test]
    fn candidate_endpoint_round_trips() {
        let ep = sample_endpoint("10.50.50.10", 9001);
        let json = serde_json::to_string(&ep).unwrap();
        let back: CandidateEndpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ip, ep.ip);
        assert_eq!(back.port, 9001);
        assert_eq!(back.status, CandidateStatus::Discovered);
        assert_eq!(back.trigger, DiscoveryTrigger::Startup);
    }

    #[test]
    fn candidate_status_serialises_as_snake_case() {
        let v = serde_json::to_value(CandidateStatus::ProbeValidated).unwrap();
        assert_eq!(v, "probe_validated");

        let v = serde_json::to_value(CandidateStatus::FlowConfirmed).unwrap();
        assert_eq!(v, "flow_confirmed");

        let v = serde_json::to_value(CandidateStatus::Rejected).unwrap();
        assert_eq!(v, "rejected");
    }

    #[test]
    fn discovery_trigger_serialises_as_snake_case() {
        let v = serde_json::to_value(DiscoveryTrigger::EbpfNewOutboundHost).unwrap();
        assert_eq!(v, "ebpf_new_outbound_host");

        let v = serde_json::to_value(DiscoveryTrigger::Scheduled).unwrap();
        assert_eq!(v, "scheduled");
    }

    #[test]
    fn discovery_report_round_trips() {
        let report = CandidateDiscoveryReport {
            discovering_agent: "agent-b".to_string(),
            scope: DiscoveryScope {
                cidrs: vec!["10.50.0.0/16".to_string()],
                ports: vec![9001, 9002],
                timeout_ms: 1500,
                max_candidates: 50,
            },
            candidates: vec![
                sample_endpoint("10.50.50.10", 9001),
                sample_endpoint("10.50.50.10", 9002),
            ],
            discovered_at: Utc::now(),
        };

        let json = serde_json::to_string(&report).unwrap();
        let back: CandidateDiscoveryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.discovering_agent, "agent-b");
        assert_eq!(back.candidates.len(), 2);
        assert_eq!(back.scope.ports, vec![9001, 9002]);
        assert_eq!(back.scope.cidrs, vec!["10.50.0.0/16"]);
    }

    #[test]
    fn ipv4_and_ipv6_candidates_both_round_trip() {
        let v4 = sample_endpoint("10.50.20.10", 9001);
        let v6 = sample_endpoint("::1", 9002);

        for ep in [v4, v6] {
            let json = serde_json::to_string(&ep).unwrap();
            let back: CandidateEndpoint = serde_json::from_str(&json).unwrap();
            assert_eq!(back.ip, ep.ip);
        }
    }
}

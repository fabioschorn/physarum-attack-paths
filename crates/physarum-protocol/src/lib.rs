pub mod organism_graph;
pub use organism_graph::{
    ColonizationEvent, EventKind, OrganismEdge, OrganismGraph, OrganismNode,
};

pub mod flow_observation;
pub use flow_observation::{
    FlowDirection, FlowEvent, FlowObservation, FlowObservationAck, FlowProtocol,
};

pub mod discovery;
pub use discovery::{
    CandidateDiscoveryReport, CandidateEndpoint, CandidateStatus, DiscoveryScope, DiscoveryTrigger,
};

pub mod packet_observation;
pub use packet_observation::{
    IcmpType, PacketDirection, PacketObservation, PacketObservationAck, PacketProtocol,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type AgentId = String;

/// Full agent record kept by the coordinator, including last heartbeat time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: AgentId,
    pub address: String,
    pub probe_port: u16,
    pub last_seen: DateTime<Utc>,
}

/// Sent by an agent on startup to announce itself to the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub agent_id: AgentId,
    pub address: String,
    pub probe_port: u16,
}

/// Coordinator reply to a registration attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub registered: bool,
    pub agent_id: AgentId,
}

/// Peer entry returned by GET /peers/{agent_id} — excludes last_seen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub agent_id: AgentId,
    pub address: String,
    pub probe_port: u16,
}

/// Result of a single probe attempt, held locally by the agent before batching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub target: AgentId,
    pub success: bool,
    pub rtt_ms: Option<u64>,
}

/// Enriched probe evidence sent by an agent to POST /report.
///
/// Beyond the raw probe outcome, the agent includes a short-term summary of
/// its local observation window so the coordinator can compute a richer
/// stimulus signal (Q_ij → q_ema) rather than reacting to a single boolean.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub source: AgentId,
    pub target: AgentId,
    pub success: bool,
    pub rtt_ms: Option<u64>,
    pub observed_at: DateTime<Utc>,
    /// Fraction of recent probes that succeeded (0.0–1.0).
    pub success_rate: f64,
    /// Mean RTT of successful probes in the observation window, ms.
    pub avg_rtt_ms: f64,
    /// Mean absolute deviation of RTT samples, ms (0.0 if < 2 samples).
    pub jitter_ms: f64,
    /// Wall-clock seconds since the observation window was opened.
    pub observation_window_seconds: u64,
    /// Total probes (successes + failures) in the observation window.
    pub sample_count: u32,
}

/// Full graph state returned by GET /graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<AgentId>,
    pub edges: Vec<EdgeSnapshot>,
}

/// One directed edge within a discovered path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEdge {
    pub source: AgentId,
    pub target: AgentId,
    pub d_ij: f64,
    pub q_ema: f64,
}

/// A single path from source to target, with its adaptive score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathResult {
    /// Ordered node IDs from source to target (inclusive).
    pub nodes: Vec<AgentId>,
    /// Ordered directed edges traversed.
    pub edges: Vec<PathEdge>,
    /// Negative-log path cost score: exp(-(sum(-ln(q_ema)) + hop_weight*(hops-1))).
    /// Higher is better. Weak edges dominate cost; multi-hop incurs a small structural penalty.
    pub score: f64,
    /// Number of directed edges in this path (hops = nodes.len() - 1).
    pub hops: usize,
}

/// Response body for GET /paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsResponse {
    pub source: AgentId,
    pub target: AgentId,
    /// All discovered simple paths, sorted by score descending.
    pub paths: Vec<PathResult>,
    /// Nodes of the top-ranked path (paths[0].nodes), or empty if no paths found.
    pub selected_path: Vec<AgentId>,
    /// Paths whose score >= secondary_conduit_threshold * best_score, excluding selected_path.
    /// Models Physarum alternate-tube retention under uncertainty.
    /// secondary_conduit_threshold=0.85 is a Physarum-inspired retention policy constant
    /// (calibrated for Gate K.1; may be tuned as more topologies are validated).
    pub secondary_conduits: Vec<PathResult>,
}

/// State of a single directed edge at a point in time.
///
/// In addition to the Physarum conductivity `d_ij`, the coordinator now stores
/// the exponential moving average of the stimulus signal (`q_ema`) and the
/// latest observation-window statistics received from the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeSnapshot {
    pub source: AgentId,
    pub target: AgentId,
    pub probe_success: bool,
    /// Physarum conductivity value clamped to [0.0, 1.0].
    pub d_ij: f64,
    /// Exponential moving average of Q_ij (stimulus signal), [0.0, 1.0].
    pub q_ema: f64,
    /// Latest success_rate from the reporting agent's observation window.
    pub success_rate: f64,
    /// Latest avg_rtt_ms from the reporting agent's observation window.
    pub avg_rtt_ms: f64,
    /// Latest jitter_ms from the reporting agent's observation window.
    pub jitter_ms: f64,
    /// Latest sample_count from the reporting agent's observation window.
    pub sample_count: u32,
    pub last_seen: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_request_round_trips() {
        let req = RegisterRequest {
            agent_id: "agent-b".to_string(),
            address: "192.168.56.11".to_string(),
            probe_port: 9001,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RegisterRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, req.agent_id);
        assert_eq!(back.probe_port, req.probe_port);
    }

    #[test]
    fn probe_report_round_trips() {
        let report = ProbeReport {
            source: "agent-b".to_string(),
            target: "agent-c".to_string(),
            success: true,
            rtt_ms: Some(7),
            observed_at: Utc::now(),
            success_rate: 0.9,
            avg_rtt_ms: 7.5,
            jitter_ms: 1.2,
            observation_window_seconds: 60,
            sample_count: 12,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: ProbeReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.source, report.source);
        assert_eq!(back.rtt_ms, Some(7));
        assert!((back.success_rate - 0.9).abs() < 1e-12);
        assert!((back.avg_rtt_ms - 7.5).abs() < 1e-12);
        assert!((back.jitter_ms - 1.2).abs() < 1e-12);
        assert_eq!(back.sample_count, 12);
    }

    #[test]
    fn enriched_probe_report_new_fields_serialize() {
        let report = ProbeReport {
            source: "b".to_string(),
            target: "c".to_string(),
            success: false,
            rtt_ms: None,
            observed_at: Utc::now(),
            success_rate: 0.0,
            avg_rtt_ms: 0.0,
            jitter_ms: 0.0,
            observation_window_seconds: 10,
            sample_count: 5,
        };
        let v: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(v["success_rate"], 0.0);
        assert_eq!(v["sample_count"], 5);
        assert_eq!(v["observation_window_seconds"], 10);
    }

    #[test]
    fn edge_snapshot_d_ij_bounds() {
        let edge = EdgeSnapshot {
            source: "agent-b".to_string(),
            target: "agent-c".to_string(),
            probe_success: true,
            d_ij: 0.72,
            q_ema: 0.85,
            success_rate: 1.0,
            avg_rtt_ms: 7.5,
            jitter_ms: 0.5,
            sample_count: 10,
            last_seen: Utc::now(),
        };
        assert!((0.0..=1.0).contains(&edge.d_ij));
        assert!((0.0..=1.0).contains(&edge.q_ema));
    }

    #[test]
    fn graph_snapshot_round_trips() {
        let snapshot = GraphSnapshot {
            nodes: vec!["agent-b".to_string(), "agent-c".to_string()],
            edges: vec![],
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let back: GraphSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nodes.len(), 2);
    }
}

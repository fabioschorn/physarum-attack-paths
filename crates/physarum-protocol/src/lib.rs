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

/// Probe evidence sent by an agent to POST /report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub source: AgentId,
    pub target: AgentId,
    pub success: bool,
    pub rtt_ms: Option<u64>,
    pub observed_at: DateTime<Utc>,
}

/// Full graph state returned by GET /graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<AgentId>,
    pub edges: Vec<EdgeSnapshot>,
}

/// State of a single directed edge at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeSnapshot {
    pub source: AgentId,
    pub target: AgentId,
    pub probe_success: bool,
    /// Physarum conductivity value clamped to [0.0, 1.0].
    pub d_ij: f64,
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
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: ProbeReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.source, report.source);
        assert_eq!(back.rtt_ms, Some(7));
    }

    #[test]
    fn edge_snapshot_d_ij_bounds() {
        let edge = EdgeSnapshot {
            source: "agent-b".to_string(),
            target: "agent-c".to_string(),
            probe_success: true,
            d_ij: 0.72,
            last_seen: Utc::now(),
        };
        assert!(edge.d_ij >= 0.0 && edge.d_ij <= 1.0);
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

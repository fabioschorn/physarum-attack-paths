use physarum_protocol::{AgentId, AgentInfo, CandidateEndpoint, EdgeSnapshot, FlowObservation};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use tokio::sync::RwLock;

pub const FLOW_BUFFER_CAPACITY: usize = 1000;

pub struct AppState {
    pub agents: RwLock<HashMap<AgentId, AgentInfo>>,
    pub edges: RwLock<HashMap<(AgentId, AgentId), EdgeSnapshot>>,
    pub flow_observations: RwLock<VecDeque<FlowObservation>>,
    // Key: (discovered_by, ip, port) — separate entries per discovering agent.
    // Two agents discovering the same (ip, port) create independent entries,
    // preserving provenance and enabling per-agent filtering without data loss.
    pub candidates: RwLock<HashMap<(String, IpAddr, u16), CandidateEndpoint>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            edges: RwLock::new(HashMap::new()),
            flow_observations: RwLock::new(VecDeque::with_capacity(FLOW_BUFFER_CAPACITY)),
            candidates: RwLock::new(HashMap::new()),
        }
    }
}

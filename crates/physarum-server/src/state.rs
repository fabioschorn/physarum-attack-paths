use physarum_protocol::{AgentId, AgentInfo, CandidateEndpoint, EdgeSnapshot, FlowObservation};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use tokio::sync::RwLock;

pub const FLOW_BUFFER_CAPACITY: usize = 1000;

pub struct AppState {
    pub agents: RwLock<HashMap<AgentId, AgentInfo>>,
    pub edges: RwLock<HashMap<(AgentId, AgentId), EdgeSnapshot>>,
    pub flow_observations: RwLock<VecDeque<FlowObservation>>,
    pub candidates: RwLock<HashMap<(IpAddr, u16), CandidateEndpoint>>,
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

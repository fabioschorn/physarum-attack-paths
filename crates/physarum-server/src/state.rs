use physarum_protocol::{AgentId, AgentInfo, EdgeSnapshot};
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct AppState {
    pub agents: RwLock<HashMap<AgentId, AgentInfo>>,
    pub edges: RwLock<HashMap<(AgentId, AgentId), EdgeSnapshot>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            edges: RwLock::new(HashMap::new()),
        }
    }
}

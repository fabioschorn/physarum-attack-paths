use physarum_protocol::{AgentId, AgentInfo};
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct AppState {
    pub agents: RwLock<HashMap<AgentId, AgentInfo>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
        }
    }
}

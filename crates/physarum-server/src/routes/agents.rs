use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use physarum_protocol::{AgentId, AgentInfo, PeerInfo, RegisterRequest, RegisterResponse};
use std::sync::Arc;

use crate::state::AppState;

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<RegisterResponse>) {
    let info = AgentInfo {
        agent_id: req.agent_id.clone(),
        address: req.address.clone(),
        probe_port: req.probe_port,
        last_seen: Utc::now(),
    };

    state
        .agents
        .write()
        .await
        .insert(req.agent_id.clone(), info);

    tracing::info!(agent_id = %req.agent_id, address = %req.address, "agent registered");

    (
        StatusCode::OK,
        Json(RegisterResponse {
            registered: true,
            agent_id: req.agent_id,
        }),
    )
}

pub async fn list_agents(State(state): State<Arc<AppState>>) -> Json<Vec<AgentInfo>> {
    let agents = state.agents.read().await;
    Json(agents.values().cloned().collect())
}

pub async fn get_peers(
    Path(agent_id): Path<AgentId>,
    State(state): State<Arc<AppState>>,
) -> Json<Vec<PeerInfo>> {
    let agents = state.agents.read().await;
    let peers = agents
        .values()
        .filter(|a| a.agent_id != agent_id)
        .map(|a| PeerInfo {
            agent_id: a.agent_id.clone(),
            address: a.address.clone(),
            probe_port: a.probe_port,
        })
        .collect();
    Json(peers)
}

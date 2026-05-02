use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use physarum_protocol::{AgentInfo, RegisterRequest, RegisterResponse};
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

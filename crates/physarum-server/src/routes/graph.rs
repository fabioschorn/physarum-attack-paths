use axum::{extract::State, Json};
use physarum_protocol::GraphSnapshot;
use std::sync::Arc;

use crate::state::AppState;

pub async fn get_graph(State(state): State<Arc<AppState>>) -> Json<GraphSnapshot> {
    let agents = state.agents.read().await;
    let edges = state.edges.read().await;

    Json(GraphSnapshot {
        nodes: agents.keys().cloned().collect(),
        edges: edges.values().cloned().collect(),
    })
}

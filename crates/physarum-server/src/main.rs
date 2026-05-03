use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod routes;
mod state;

use state::AppState;

#[derive(Parser)]
#[command(name = "physarum-server", about = "Physarum attack-path coordinator")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080", env = "PHYSARUM_LISTEN")]
    listen: SocketAddr,
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(routes::health::health))
        .route("/register", post(routes::agents::register))
        .route("/agents", get(routes::agents::list_agents))
        .route("/peers/:agent_id", get(routes::agents::get_peers))
        .route("/report", post(routes::reports::ingest_report))
        .route("/graph", get(routes::graph::get_graph))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let state = Arc::new(AppState::new());
    let app = build_router(state);

    tracing::info!("physarum-server listening on {}", cli.listen);

    let listener = tokio::net::TcpListener::bind(cli.listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use chrono::Utc;
    use http_body_util::BodyExt;
    use physarum_protocol::{GraphSnapshot, PeerInfo, ProbeReport, RegisterRequest};
    use tower::ServiceExt;

    async fn register_agent(state: Arc<AppState>, id: &str, port: u16) {
        let req = RegisterRequest {
            agent_id: id.to_string(),
            address: "127.0.0.1".to_string(),
            probe_port: port,
        };
        let request = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&req).unwrap()))
            .unwrap();
        build_router(state).oneshot(request).await.unwrap();
    }

    async fn send_report(state: Arc<AppState>, src: &str, dst: &str, success: bool) {
        let report = ProbeReport {
            source: src.to_string(),
            target: dst.to_string(),
            success,
            rtt_ms: if success { Some(7) } else { None },
            observed_at: Utc::now(),
        };
        let request = Request::builder()
            .method("POST")
            .uri("/report")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&report).unwrap()))
            .unwrap();
        build_router(state).oneshot(request).await.unwrap();
    }

    #[tokio::test]
    async fn peers_excludes_requesting_agent() {
        let state = Arc::new(AppState::new());
        register_agent(state.clone(), "agent-b", 9001).await;
        register_agent(state.clone(), "agent-c", 9002).await;

        let request = Request::builder()
            .uri("/peers/agent-b")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();

        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let peers: Vec<PeerInfo> = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].agent_id, "agent-c");
        assert!(!peers.iter().any(|p| p.agent_id == "agent-b"));
    }

    #[tokio::test]
    async fn report_creates_directed_edge() {
        let state = Arc::new(AppState::new());
        send_report(state.clone(), "agent-b", "agent-c", true).await;

        let edges = state.edges.read().await;
        let key = ("agent-b".to_string(), "agent-c".to_string());
        assert!(edges.contains_key(&key), "edge agent-b -> agent-c not found");
    }

    #[tokio::test]
    async fn success_increases_d_ij() {
        let state = Arc::new(AppState::new());
        send_report(state.clone(), "b", "c", true).await;

        let edges = state.edges.read().await;
        let d = edges[&("b".to_string(), "c".to_string())].d_ij;
        assert!(d > 0.0, "D_ij should be > 0.0 after success, got {d}");
    }

    #[tokio::test]
    async fn failure_decreases_d_ij() {
        let state = Arc::new(AppState::new());
        // Establish a positive D_ij via success first.
        send_report(state.clone(), "b", "c", true).await;
        let d_after_success = state.edges.read().await
            [&("b".to_string(), "c".to_string())].d_ij;

        send_report(state.clone(), "b", "c", false).await;
        let d_after_failure = state.edges.read().await
            [&("b".to_string(), "c".to_string())].d_ij;

        assert!(
            d_after_failure < d_after_success,
            "D_ij should decrease after failure: {d_after_success} -> {d_after_failure}"
        );
    }

    #[tokio::test]
    async fn d_ij_stays_clamped_to_unit_interval() {
        let state = Arc::new(AppState::new());
        for _ in 0..50 {
            send_report(state.clone(), "b", "c", true).await;
        }
        let d = state.edges.read().await[&("b".to_string(), "c".to_string())].d_ij;
        assert!((0.0..=1.0).contains(&d), "D_ij out of [0,1]: got {d}");
    }

    #[tokio::test]
    async fn graph_returns_nodes_and_edges() {
        let state = Arc::new(AppState::new());
        register_agent(state.clone(), "agent-b", 9001).await;
        register_agent(state.clone(), "agent-c", 9002).await;
        send_report(state.clone(), "agent-b", "agent-c", true).await;

        let request = Request::builder()
            .uri("/graph")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();

        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let snapshot: GraphSnapshot = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(snapshot.nodes.len(), 2);
        assert_eq!(snapshot.edges.len(), 1);
        let edge = &snapshot.edges[0];
        assert_eq!(edge.source, "agent-b");
        assert_eq!(edge.target, "agent-c");
        assert!((0.0..=1.0).contains(&edge.d_ij));
    }
}

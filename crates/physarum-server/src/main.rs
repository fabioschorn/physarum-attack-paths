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
        .route("/paths", get(routes::paths::get_paths))
        .route(
            "/flow-observations",
            post(routes::flow_observations::ingest_flow_observation)
                .get(routes::flow_observations::list_flow_observations),
        )
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
    use physarum_protocol::{GraphSnapshot, PathsResponse, PeerInfo, ProbeReport, RegisterRequest};
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

    async fn send_report(
        state: Arc<AppState>,
        src: &str,
        dst: &str,
        success: bool,
        success_rate: f64,
        avg_rtt_ms: f64,
    ) {
        let report = ProbeReport {
            source: src.to_string(),
            target: dst.to_string(),
            success,
            rtt_ms: if success { Some(7) } else { None },
            observed_at: Utc::now(),
            success_rate,
            avg_rtt_ms,
            jitter_ms: 0.0,
            observation_window_seconds: 0,
            sample_count: 1,
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
        send_report(state.clone(), "agent-b", "agent-c", true, 1.0, 7.0).await;

        let edges = state.edges.read().await;
        let key = ("agent-b".to_string(), "agent-c".to_string());
        assert!(
            edges.contains_key(&key),
            "edge agent-b -> agent-c not found"
        );
    }

    #[tokio::test]
    async fn success_increases_d_ij() {
        let state = Arc::new(AppState::new());
        send_report(state.clone(), "b", "c", true, 1.0, 7.0).await;

        let edges = state.edges.read().await;
        let d = edges[&("b".to_string(), "c".to_string())].d_ij;
        assert!(d > 0.0, "D_ij should be > 0.0 after success, got {d}");
    }

    #[tokio::test]
    async fn sustained_failures_drain_d_ij() {
        let state = Arc::new(AppState::new());
        // Establish D_ij via successes.
        for _ in 0..10 {
            send_report(state.clone(), "b", "c", true, 1.0, 7.0).await;
        }
        let d_peak = state.edges.read().await[&("b".to_string(), "c".to_string())].d_ij;

        // Sustained all-failure reports: success_rate=0.0 → Q_ij=0 → q_ema→0 → pure decay.
        for _ in 0..50 {
            send_report(state.clone(), "b", "c", false, 0.0, 0.0).await;
        }
        let d_after = state.edges.read().await[&("b".to_string(), "c".to_string())].d_ij;

        assert!(
            d_after < d_peak,
            "D_ij should drain under sustained failures: peak={d_peak} -> after={d_after}"
        );
    }

    #[tokio::test]
    async fn d_ij_stays_clamped_to_unit_interval() {
        let state = Arc::new(AppState::new());
        for _ in 0..50 {
            send_report(state.clone(), "b", "c", true, 1.0, 7.0).await;
        }
        let d = state.edges.read().await[&("b".to_string(), "c".to_string())].d_ij;
        assert!((0.0..=1.0).contains(&d), "D_ij out of [0,1]: got {d}");
    }

    #[tokio::test]
    async fn graph_returns_nodes_edges_and_q_ema() {
        let state = Arc::new(AppState::new());
        register_agent(state.clone(), "agent-b", 9001).await;
        register_agent(state.clone(), "agent-c", 9002).await;
        send_report(state.clone(), "agent-b", "agent-c", true, 1.0, 7.0).await;

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
        assert!(edge.q_ema > 0.0, "q_ema should be > 0.0 after success");
        assert!((0.0..=1.0).contains(&edge.q_ema));
    }

    // ── /paths tests ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn paths_missing_source_returns_400() {
        let state = Arc::new(AppState::new());
        let request = Request::builder()
            .uri("/paths?target=agent-d")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn paths_missing_target_returns_400() {
        let state = Arc::new(AppState::new());
        let request = Request::builder()
            .uri("/paths?source=agent-b")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn paths_unknown_agents_returns_empty() {
        let state = Arc::new(AppState::new());
        let request = Request::builder()
            .uri("/paths?source=agent-x&target=agent-z")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let pr: PathsResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(pr.paths.is_empty(), "no known edges → no paths");
    }

    #[tokio::test]
    async fn paths_source_equals_target_returns_empty() {
        let state = Arc::new(AppState::new());
        let request = Request::builder()
            .uri("/paths?source=agent-b&target=agent-b")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let pr: PathsResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(pr.paths.is_empty(), "source==target should yield no paths");
    }

    #[tokio::test]
    async fn paths_b_to_d_via_c_found() {
        let state = Arc::new(AppState::new());
        // Only provide b→c and c→d: single path exists.
        send_report(state.clone(), "agent-b", "agent-c", true, 1.0, 0.0).await;
        send_report(state.clone(), "agent-c", "agent-d", true, 1.0, 0.0).await;

        let request = Request::builder()
            .uri("/paths?source=agent-b&target=agent-d")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let pr: PathsResponse = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(pr.paths.len(), 1, "exactly one path: b→c→d");
        let path = &pr.paths[0];
        assert_eq!(path.nodes, vec!["agent-b", "agent-c", "agent-d"]);
        assert_eq!(path.edges.len(), 2);
        assert_eq!(path.hops, 2);
        assert_eq!(path.edges[0].source, "agent-b");
        assert_eq!(path.edges[0].target, "agent-c");
        assert_eq!(path.edges[1].source, "agent-c");
        assert_eq!(path.edges[1].target, "agent-d");
        assert_eq!(pr.selected_path, vec!["agent-b", "agent-c", "agent-d"]);
    }

    #[tokio::test]
    async fn paths_score_uses_negative_log_q_ema() {
        let state = Arc::new(AppState::new());
        send_report(state.clone(), "agent-b", "agent-c", true, 1.0, 0.0).await;
        send_report(state.clone(), "agent-c", "agent-d", true, 1.0, 0.0).await;

        let request = Request::builder()
            .uri("/paths?source=agent-b&target=agent-d")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let pr: PathsResponse = serde_json::from_slice(&bytes).unwrap();

        for path in &pr.paths {
            let edge_cost: f64 = path
                .edges
                .iter()
                .map(|e| -(e.q_ema.max(0.001_f64).ln()))
                .sum();
            let hop_penalty = 0.05 * (path.edges.len().saturating_sub(1)) as f64;
            let expected = (-(edge_cost + hop_penalty)).exp();
            assert!(
                (path.score - expected).abs() < 1e-12,
                "score {:.6} != negative-log(q_ema) expected {:.6}",
                path.score,
                expected,
            );
        }
    }

    #[tokio::test]
    async fn paths_max_depth_limits_path_length() {
        let state = Arc::new(AppState::new());
        // b→c, c→d, and direct b→d
        send_report(state.clone(), "agent-b", "agent-c", true, 1.0, 0.0).await;
        send_report(state.clone(), "agent-c", "agent-d", true, 1.0, 0.0).await;
        send_report(state.clone(), "agent-b", "agent-d", true, 1.0, 0.0).await;

        let request = Request::builder()
            .uri("/paths?source=agent-b&target=agent-d&max_depth=1")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let pr: PathsResponse = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(pr.paths.len(), 1, "only direct b→d with max_depth=1");
        assert_eq!(pr.paths[0].edges.len(), 1);
    }

    #[tokio::test]
    async fn paths_sorted_by_score_descending() {
        let state = Arc::new(AppState::new());
        // b→d direct after one report (lower d_ij than b→c→d after many)
        send_report(state.clone(), "agent-b", "agent-c", true, 1.0, 0.0).await;
        send_report(state.clone(), "agent-c", "agent-d", true, 1.0, 0.0).await;
        send_report(state.clone(), "agent-b", "agent-d", true, 1.0, 0.0).await;

        let request = Request::builder()
            .uri("/paths?source=agent-b&target=agent-d")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let pr: PathsResponse = serde_json::from_slice(&bytes).unwrap();

        let scores: Vec<f64> = pr.paths.iter().map(|p| p.score).collect();
        let mut sorted = scores.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
        assert_eq!(scores, sorted, "paths must be sorted by score descending");
    }
}

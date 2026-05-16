use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use physarum_protocol::{CandidateDiscoveryReport, CandidateEndpoint};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
    pub agent_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CandidateDiscoveryAck {
    pub stored: usize,
}

pub async fn ingest_candidate_discovery(
    State(state): State<Arc<AppState>>,
    Json(report): Json<CandidateDiscoveryReport>,
) -> (StatusCode, Json<CandidateDiscoveryAck>) {
    let discovering_agent = report.discovering_agent.clone();
    let count = report.candidates.len();
    let mut store = state.candidates.write().await;
    for candidate in report.candidates {
        store.insert((candidate.ip, candidate.port), candidate);
    }
    tracing::info!(
        agent = %discovering_agent,
        stored = count,
        "candidate discovery report ingested"
    );
    (
        StatusCode::CREATED,
        Json(CandidateDiscoveryAck { stored: count }),
    )
}

pub async fn list_candidate_discoveries(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListQuery>,
) -> Json<Vec<CandidateEndpoint>> {
    let store = state.candidates.read().await;
    let limit = params.limit.unwrap_or(store.len());

    let results: Vec<CandidateEndpoint> = store
        .values()
        .filter(|c| {
            params
                .agent_id
                .as_deref()
                .map_or(true, |id| c.discovered_by == id)
        })
        .take(limit)
        .cloned()
        .collect();

    Json(results)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::{body::Body, http::Request, routing::post, Router};
    use chrono::Utc;
    use http_body_util::BodyExt;
    use physarum_protocol::{CandidateStatus, DiscoveryScope, DiscoveryTrigger};
    use tower::ServiceExt;

    fn build_test_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route(
                "/candidate-discoveries",
                post(ingest_candidate_discovery).get(list_candidate_discoveries),
            )
            .with_state(state)
    }

    fn make_report(agent_id: &str, candidates: Vec<CandidateEndpoint>) -> CandidateDiscoveryReport {
        CandidateDiscoveryReport {
            discovering_agent: agent_id.to_string(),
            scope: DiscoveryScope {
                cidrs: vec!["10.0.0.0/30".to_string()],
                ports: vec![9001],
                timeout_ms: 500,
                max_candidates: 50,
            },
            candidates,
            discovered_at: Utc::now(),
        }
    }

    fn make_candidate(agent_id: &str, ip: &str, port: u16) -> CandidateEndpoint {
        CandidateEndpoint {
            discovered_by: agent_id.to_string(),
            ip: ip.parse().unwrap(),
            port,
            protocol: "tcp".to_string(),
            discovery_method: "physarum-scanner".to_string(),
            discovered_at: Utc::now(),
            status: CandidateStatus::Discovered,
            confidence: 0.0,
            trigger: DiscoveryTrigger::Scheduled,
        }
    }

    async fn post_report(
        router: Router,
        report: &CandidateDiscoveryReport,
    ) -> axum::response::Response {
        let req = Request::builder()
            .method("POST")
            .uri("/candidate-discoveries")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(report).unwrap()))
            .unwrap();
        router.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn post_valid_report_returns_201() {
        let state = Arc::new(AppState::new());
        let report = make_report("agent-b", vec![make_candidate("agent-b", "10.0.0.1", 9001)]);
        let resp = post_report(build_test_router(state), &report).await;
        assert_eq!(resp.status(), 201);
    }

    #[tokio::test]
    async fn ack_body_contains_stored_count() {
        let state = Arc::new(AppState::new());
        let report = make_report(
            "agent-b",
            vec![
                make_candidate("agent-b", "10.0.0.1", 9001),
                make_candidate("agent-b", "10.0.0.2", 9001),
            ],
        );
        let resp = post_report(build_test_router(state), &report).await;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let ack: CandidateDiscoveryAck = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ack.stored, 2);
    }

    #[tokio::test]
    async fn posted_candidates_appear_in_get() {
        let state = Arc::new(AppState::new());
        let report = make_report("agent-b", vec![make_candidate("agent-b", "10.0.0.1", 9001)]);
        post_report(build_test_router(state.clone()), &report).await;

        let req = Request::builder()
            .uri("/candidate-discoveries")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<CandidateEndpoint> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].ip, "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(list[0].port, 9001);
    }

    #[tokio::test]
    async fn get_with_agent_id_filters_correctly() {
        let state = Arc::new(AppState::new());
        let report_b = make_report("agent-b", vec![make_candidate("agent-b", "10.0.0.1", 9001)]);
        let report_c = make_report("agent-c", vec![make_candidate("agent-c", "10.0.0.2", 9001)]);
        post_report(build_test_router(state.clone()), &report_b).await;
        post_report(build_test_router(state.clone()), &report_c).await;

        let req = Request::builder()
            .uri("/candidate-discoveries?agent_id=agent-b")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<CandidateEndpoint> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].discovered_by, "agent-b");
    }

    #[tokio::test]
    async fn get_with_limit_returns_at_most_n() {
        let state = Arc::new(AppState::new());
        let candidates: Vec<_> = (1u8..=5)
            .map(|i| make_candidate("agent-b", &format!("10.0.0.{i}"), 9001))
            .collect();
        let report = make_report("agent-b", candidates);
        post_report(build_test_router(state.clone()), &report).await;

        let req = Request::builder()
            .uri("/candidate-discoveries?limit=2")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<CandidateEndpoint> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn upsert_replaces_same_ip_port() {
        let state = Arc::new(AppState::new());

        // agent-b discovers 10.0.0.1:9001
        let report_b = make_report("agent-b", vec![make_candidate("agent-b", "10.0.0.1", 9001)]);
        post_report(build_test_router(state.clone()), &report_b).await;

        // agent-c also discovers the same socket — should overwrite
        let report_c = make_report("agent-c", vec![make_candidate("agent-c", "10.0.0.1", 9001)]);
        post_report(build_test_router(state.clone()), &report_c).await;

        let store = state.candidates.read().await;
        assert_eq!(store.len(), 1, "same (ip,port) deduplicates to one entry");
        let entry = &store[&("10.0.0.1".parse().unwrap(), 9001u16)];
        assert_eq!(
            entry.discovered_by, "agent-c",
            "latest agent wins on upsert"
        );
    }

    #[tokio::test]
    async fn empty_candidates_accepted() {
        let state = Arc::new(AppState::new());
        let report = make_report("agent-b", vec![]);
        let resp = post_report(build_test_router(state), &report).await;
        assert_eq!(resp.status(), 201);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let ack: CandidateDiscoveryAck = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ack.stored, 0);
    }

    #[tokio::test]
    async fn invalid_payload_returns_422() {
        let state = Arc::new(AppState::new());
        let req = Request::builder()
            .method("POST")
            .uri("/candidate-discoveries")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"not":"valid"}"#))
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 422);
    }
}

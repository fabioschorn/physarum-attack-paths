use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use physarum_protocol::{FlowObservation, FlowObservationAck};
use serde::Deserialize;
use std::sync::Arc;

use crate::state::{AppState, FLOW_BUFFER_CAPACITY};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
    pub agent_id: Option<String>,
    /// Return only observations with `observed_at` strictly after this timestamp (RFC3339).
    pub since: Option<DateTime<Utc>>,
}

pub async fn ingest_flow_observation(
    State(state): State<Arc<AppState>>,
    Json(obs): Json<FlowObservation>,
) -> (StatusCode, Json<FlowObservationAck>) {
    let mut buf = state.flow_observations.write().await;
    if buf.len() == FLOW_BUFFER_CAPACITY {
        buf.pop_front();
    }

    tracing::info!(
        agent_id = %obs.agent_id,
        event    = ?obs.event,
        src      = %obs.source_ip,
        dst      = %obs.destination_ip,
        dst_port = obs.destination_port,
        pid      = obs.pid,
        comm     = %obs.comm,
        "flow observation ingested"
    );

    buf.push_back(obs);
    (
        StatusCode::CREATED,
        Json(FlowObservationAck { accepted: true }),
    )
}

pub async fn list_flow_observations(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListQuery>,
) -> Json<Vec<FlowObservation>> {
    let buf = state.flow_observations.read().await;
    let limit = params.limit.unwrap_or(buf.len()).min(buf.len());

    let results: Vec<FlowObservation> = buf
        .iter()
        .rev()
        .filter(|obs| {
            params
                .agent_id
                .as_deref()
                .is_none_or(|id| obs.agent_id == id)
                && params.since.is_none_or(|since| obs.observed_at > since)
        })
        .take(limit)
        .cloned()
        .collect();

    Json(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::{
        body::Body,
        http::Request,
        routing::{get, post},
        Router,
    };
    use chrono::Utc;
    use http_body_util::BodyExt;
    use physarum_protocol::{FlowDirection, FlowEvent, FlowProtocol};
    use tower::ServiceExt;

    fn build_test_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/flow-observations", post(ingest_flow_observation))
            .route("/flow-observations", get(list_flow_observations))
            .with_state(state)
    }

    fn make_obs(agent_id: &str, dst_port: u16) -> FlowObservation {
        FlowObservation {
            agent_id: agent_id.to_string(),
            observed_at: Utc::now(),
            source_ip: "10.0.0.1".to_string(),
            source_port: 55000,
            destination_ip: "10.0.0.2".to_string(),
            destination_port: dst_port,
            protocol: FlowProtocol::Tcp,
            direction: FlowDirection::Outbound,
            event: FlowEvent::ConnectEstablished,
            pid: 42,
            comm: "test-proc".to_string(),
        }
    }

    async fn post_obs(router: Router, obs: &FlowObservation) -> axum::http::StatusCode {
        let req = Request::builder()
            .method("POST")
            .uri("/flow-observations")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(obs).unwrap()))
            .unwrap();
        router.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn post_valid_observation_returns_201() {
        let state = Arc::new(AppState::new());
        let status = post_obs(build_test_router(state), &make_obs("agent-b", 9002)).await;
        assert_eq!(status, 201);
    }

    #[tokio::test]
    async fn posted_observation_appears_in_get() {
        let state = Arc::new(AppState::new());
        let obs = make_obs("agent-b", 9002);
        post_obs(build_test_router(state.clone()), &obs).await;

        let req = Request::builder()
            .uri("/flow-observations")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<FlowObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].agent_id, "agent-b");
        assert_eq!(list[0].destination_port, 9002);
    }

    #[tokio::test]
    async fn get_with_limit_returns_at_most_n() {
        let state = Arc::new(AppState::new());
        for port in 9000..9010_u16 {
            post_obs(build_test_router(state.clone()), &make_obs("agent-b", port)).await;
        }

        let req = Request::builder()
            .uri("/flow-observations?limit=3")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<FlowObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn get_with_agent_id_filters_correctly() {
        let state = Arc::new(AppState::new());
        post_obs(build_test_router(state.clone()), &make_obs("agent-b", 9001)).await;
        post_obs(build_test_router(state.clone()), &make_obs("agent-c", 9002)).await;
        post_obs(build_test_router(state.clone()), &make_obs("agent-b", 9003)).await;

        let req = Request::builder()
            .uri("/flow-observations?agent_id=agent-b")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<FlowObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|o| o.agent_id == "agent-b"));
    }

    #[tokio::test]
    async fn get_with_since_filters_old_observations() {
        let state = Arc::new(AppState::new());

        // Post an old observation with a fixed timestamp in the past.
        let mut old_obs = make_obs("agent-b", 9001);
        old_obs.observed_at = DateTime::from_timestamp(0, 0).unwrap(); // epoch
        post_obs(build_test_router(state.clone()), &old_obs).await;

        // Post a new observation with a recent timestamp.
        let mut new_obs = make_obs("agent-b", 9002);
        new_obs.observed_at = Utc::now();
        post_obs(build_test_router(state.clone()), &new_obs).await;

        // Query with since=1970-01-01T00:00:01Z — should exclude the epoch observation.
        let since = DateTime::from_timestamp(1, 0).unwrap();
        let encoded_since: String = since
            .to_rfc3339()
            .chars()
            .flat_map(|c| match c {
                ':' => vec!['%', '3', 'A'],
                '+' => vec!['%', '2', 'B'],
                _ => vec![c],
            })
            .collect();
        let req = Request::builder()
            .uri(format!("/flow-observations?since={encoded_since}"))
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<FlowObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].destination_port, 9002);
    }

    #[tokio::test]
    async fn invalid_payload_returns_422() {
        let state = Arc::new(AppState::new());
        let req = Request::builder()
            .method("POST")
            .uri("/flow-observations")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"not":"valid"}"#))
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn buffer_evicts_oldest_when_full() {
        let state = Arc::new(AppState::new());
        // Fill buffer to capacity + 1
        for port in 0..=(FLOW_BUFFER_CAPACITY as u16) {
            post_obs(build_test_router(state.clone()), &make_obs("agent-b", port)).await;
        }

        let buf = state.flow_observations.read().await;
        assert_eq!(buf.len(), FLOW_BUFFER_CAPACITY);
        // oldest (port 0) should be gone; newest (port CAPACITY) should be present
        assert!(buf.iter().all(|o| o.destination_port != 0));
        assert!(buf
            .iter()
            .any(|o| o.destination_port == FLOW_BUFFER_CAPACITY as u16));
    }
}

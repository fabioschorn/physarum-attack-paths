use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use physarum_protocol::{PacketObservation, PacketObservationAck};
use serde::Deserialize;
use std::sync::Arc;

use crate::state::{AppState, PACKET_BUFFER_CAPACITY};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
    pub agent_id: Option<String>,
    /// Filter by protocol (e.g. "icmp"). Case-insensitive match against serialised value.
    pub protocol: Option<String>,
    /// Return only observations with `observed_at` strictly after this timestamp (RFC3339).
    pub since: Option<DateTime<Utc>>,
}

pub async fn ingest_packet_observation(
    State(state): State<Arc<AppState>>,
    Json(obs): Json<PacketObservation>,
) -> (StatusCode, Json<PacketObservationAck>) {
    let mut buf = state.packet_observations.write().await;
    if buf.len() == PACKET_BUFFER_CAPACITY {
        buf.pop_front();
    }

    tracing::info!(
        agent_id   = %obs.agent_id,
        icmp_type  = ?obs.icmp_type,
        icmp_code  = obs.icmp_code,
        src        = %obs.source_ip,
        dst        = %obs.destination_ip,
        iface      = %obs.interface_name,
        "packet observation ingested"
    );

    buf.push_back(obs);
    (
        StatusCode::CREATED,
        Json(PacketObservationAck { accepted: true }),
    )
}

pub async fn list_packet_observations(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListQuery>,
) -> Json<Vec<PacketObservation>> {
    let buf = state.packet_observations.read().await;
    let limit = params.limit.unwrap_or(buf.len()).min(buf.len());

    let results: Vec<PacketObservation> = buf
        .iter()
        .rev()
        .filter(|obs| {
            params
                .agent_id
                .as_deref()
                .map_or(true, |id| obs.agent_id == id)
                && params.protocol.as_deref().map_or(true, |proto| {
                    serde_json::to_value(&obs.protocol)
                        .ok()
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                        .map_or(false, |s| s.eq_ignore_ascii_case(proto))
                })
                && params.since.map_or(true, |since| obs.observed_at > since)
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
    use physarum_protocol::{IcmpType, PacketDirection, PacketProtocol};
    use tower::ServiceExt;

    fn build_test_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/packet-observations", post(ingest_packet_observation))
            .route("/packet-observations", get(list_packet_observations))
            .with_state(state)
    }

    fn make_obs(agent_id: &str, src_ip: &str) -> PacketObservation {
        PacketObservation {
            agent_id: agent_id.to_string(),
            observed_at: Utc::now(),
            source_ip: src_ip.to_string(),
            destination_ip: "10.50.20.10".to_string(),
            protocol: PacketProtocol::Icmp,
            icmp_type: IcmpType::EchoRequest,
            icmp_code: 0,
            direction: PacketDirection::Inbound,
            interface_name: "eth0".to_string(),
            packet_size: Some(64),
            ttl: Some(64),
        }
    }

    async fn post_obs(router: Router, obs: &PacketObservation) -> axum::http::StatusCode {
        let req = Request::builder()
            .method("POST")
            .uri("/packet-observations")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(obs).unwrap()))
            .unwrap();
        router.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn post_packet_observation_returns_201() {
        let state = Arc::new(AppState::new());
        let status = post_obs(
            build_test_router(state),
            &make_obs("agent-b", "10.50.20.20"),
        )
        .await;
        assert_eq!(status, 201);
    }

    #[tokio::test]
    async fn posted_observation_appears_in_get() {
        let state = Arc::new(AppState::new());
        let obs = make_obs("agent-b", "10.50.20.20");
        post_obs(build_test_router(state.clone()), &obs).await;

        let req = Request::builder()
            .uri("/packet-observations")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<PacketObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].agent_id, "agent-b");
        assert_eq!(list[0].source_ip, "10.50.20.20");
    }

    #[tokio::test]
    async fn get_filtered_by_agent_id() {
        let state = Arc::new(AppState::new());
        post_obs(
            build_test_router(state.clone()),
            &make_obs("agent-b", "10.50.20.20"),
        )
        .await;
        post_obs(
            build_test_router(state.clone()),
            &make_obs("agent-c", "10.50.20.30"),
        )
        .await;

        let req = Request::builder()
            .uri("/packet-observations?agent_id=agent-b")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<PacketObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].agent_id, "agent-b");
    }

    #[tokio::test]
    async fn get_filtered_by_protocol_icmp() {
        let state = Arc::new(AppState::new());
        post_obs(
            build_test_router(state.clone()),
            &make_obs("agent-b", "10.50.20.20"),
        )
        .await;

        let req = Request::builder()
            .uri("/packet-observations?protocol=icmp")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state.clone()).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<PacketObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);

        // Non-matching protocol returns empty
        let req = Request::builder()
            .uri("/packet-observations?protocol=tcp")
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<PacketObservation> = serde_json::from_slice(&bytes).unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn get_filtered_by_since() {
        let state = Arc::new(AppState::new());

        let mut old_obs = make_obs("agent-b", "10.50.20.20");
        old_obs.observed_at = DateTime::from_timestamp(0, 0).unwrap();
        post_obs(build_test_router(state.clone()), &old_obs).await;

        let mut new_obs = make_obs("agent-b", "10.50.20.30");
        new_obs.observed_at = Utc::now();
        post_obs(build_test_router(state.clone()), &new_obs).await;

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
            .uri(format!("/packet-observations?since={encoded_since}"))
            .body(Body::empty())
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<PacketObservation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].source_ip, "10.50.20.30");
    }

    #[tokio::test]
    async fn invalid_payload_returns_422() {
        let state = Arc::new(AppState::new());
        let req = Request::builder()
            .method("POST")
            .uri("/packet-observations")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"not":"valid"}"#))
            .unwrap();
        let resp = build_test_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn buffer_evicts_oldest_when_full() {
        let state = Arc::new(AppState::new());
        for i in 0..=(PACKET_BUFFER_CAPACITY as u32) {
            let mut obs = make_obs("agent-b", "10.50.20.20");
            // Distinguishable by icmp_code
            obs.icmp_code = (i % 256) as u8;
            obs.observed_at = DateTime::from_timestamp(i as i64, 0).unwrap();
            post_obs(build_test_router(state.clone()), &obs).await;
        }

        let buf = state.packet_observations.read().await;
        assert_eq!(buf.len(), PACKET_BUFFER_CAPACITY);
        // The oldest entry (timestamp=0) must have been evicted.
        assert!(buf
            .iter()
            .all(|o| o.observed_at > DateTime::from_timestamp(0, 0).unwrap()));
    }
}

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use physarum_protocol::{CandidateDiscoveryReport, CandidateEndpoint};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
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
        let key = (
            candidate.discovered_by.clone(),
            candidate.ip,
            candidate.port,
        );
        match store.entry(key) {
            Entry::Vacant(e) => {
                e.insert(candidate);
            }
            Entry::Occupied(mut e) => {
                // Prefer the stronger trigger: ebpf_new_outbound_host always
                // wins over scheduled/startup, so a later scheduled re-discovery
                // cannot erase eBPF provenance from the API.
                if candidate.trigger.priority() > e.get().trigger.priority() {
                    e.insert(candidate);
                }
            }
        }
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

// MVP limitation: candidate status (Discovered → ProbeValidated → FlowConfirmed) is not
// updated server-side in Gate L. The server stores what the agent reports; status transitions
// require the agent to re-POST an updated CandidateDiscoveryReport or a dedicated PATCH
// endpoint. Tracked as Gate L.1 work item.
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
                .is_none_or(|id| c.discovered_by == id)
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
    async fn different_agents_discovering_same_endpoint_creates_two_entries() {
        // Key is (discovered_by, ip, port) — provenance is preserved.
        // Two agents discovering the same socket create independent entries.
        let state = Arc::new(AppState::new());

        let report_b = make_report("agent-b", vec![make_candidate("agent-b", "10.0.0.1", 9001)]);
        let report_c = make_report("agent-c", vec![make_candidate("agent-c", "10.0.0.1", 9001)]);
        post_report(build_test_router(state.clone()), &report_b).await;
        post_report(build_test_router(state.clone()), &report_c).await;

        let store = state.candidates.read().await;
        assert_eq!(
            store.len(),
            2,
            "different agents → separate entries for same (ip,port)"
        );
    }

    #[tokio::test]
    async fn same_agent_rediscovering_same_endpoint_upserts() {
        // Same agent discovering same (ip, port) a second time with same trigger priority
        // keeps one entry — no duplicates.
        let state = Arc::new(AppState::new());

        let report1 = make_report("agent-b", vec![make_candidate("agent-b", "10.0.0.1", 9001)]);
        let report2 = make_report("agent-b", vec![make_candidate("agent-b", "10.0.0.1", 9001)]);
        post_report(build_test_router(state.clone()), &report1).await;
        post_report(build_test_router(state.clone()), &report2).await;

        let store = state.candidates.read().await;
        assert_eq!(
            store.len(),
            1,
            "same agent + same (ip,port) → single entry (upsert)"
        );
    }

    #[tokio::test]
    async fn ebpf_trigger_not_overwritten_by_later_scheduled_discovery() {
        let state = Arc::new(AppState::new());

        // eBPF trigger arrives first.
        let mut ebpf_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        ebpf_candidate.trigger = DiscoveryTrigger::EbpfNewOutboundHost;
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![ebpf_candidate]),
        )
        .await;

        // Scheduled scanner re-discovers the same endpoint later.
        let sched_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![sched_candidate]),
        )
        .await;

        let store = state.candidates.read().await;
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.values().next().unwrap().trigger,
            DiscoveryTrigger::EbpfNewOutboundHost,
            "eBPF trigger must survive a later scheduled re-discovery"
        );
    }

    #[tokio::test]
    async fn ebpf_trigger_promotes_over_earlier_scheduled_entry() {
        let state = Arc::new(AppState::new());

        // Scheduled scanner discovers first.
        let sched_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![sched_candidate]),
        )
        .await;

        // eBPF trigger arrives second — must win regardless of order.
        let mut ebpf_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        ebpf_candidate.trigger = DiscoveryTrigger::EbpfNewOutboundHost;
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![ebpf_candidate]),
        )
        .await;

        let store = state.candidates.read().await;
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.values().next().unwrap().trigger,
            DiscoveryTrigger::EbpfNewOutboundHost,
            "eBPF trigger must win even when scheduled entry arrived first"
        );
    }

    #[tokio::test]
    async fn inbound_trigger_not_overwritten_by_later_outbound() {
        // Gate L.2: inbound (priority=3) must survive a later outbound (priority=2) provenance.
        let state = Arc::new(AppState::new());

        let mut inbound_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        inbound_candidate.trigger = DiscoveryTrigger::EbpfNewInboundHost;
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![inbound_candidate]),
        )
        .await;

        let mut outbound_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        outbound_candidate.trigger = DiscoveryTrigger::EbpfNewOutboundHost;
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![outbound_candidate]),
        )
        .await;

        let store = state.candidates.read().await;
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.values().next().unwrap().trigger,
            DiscoveryTrigger::EbpfNewInboundHost,
            "inbound trigger must survive a later outbound provenance report"
        );
    }

    #[tokio::test]
    async fn inbound_trigger_promotes_over_earlier_outbound() {
        // Gate L.2: inbound (priority=3) must win even when outbound (priority=2) arrived first.
        let state = Arc::new(AppState::new());

        let mut outbound_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        outbound_candidate.trigger = DiscoveryTrigger::EbpfNewOutboundHost;
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![outbound_candidate]),
        )
        .await;

        let mut inbound_candidate = make_candidate("agent-b", "10.0.0.1", 9001);
        inbound_candidate.trigger = DiscoveryTrigger::EbpfNewInboundHost;
        post_report(
            build_test_router(state.clone()),
            &make_report("agent-b", vec![inbound_candidate]),
        )
        .await;

        let store = state.candidates.read().await;
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.values().next().unwrap().trigger,
            DiscoveryTrigger::EbpfNewInboundHost,
            "inbound trigger must win even when outbound entry arrived first"
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

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use physarum_protocol::{AgentId, EdgeSnapshot, PathEdge, PathResult, PathsResponse};
use serde::Deserialize;
use std::{collections::HashMap, collections::HashSet, sync::Arc};

use crate::state::AppState;

/// Penalty added per additional hop beyond the first.
///
/// hop_weight=0.05 is calibrated for Gate K.1: it prefers the direct path when
/// all candidates are healthy, while allowing a healthy multi-hop path to beat a
/// degraded direct path. Future topologies may require re-calibration.
const HOP_WEIGHT: f64 = 0.05;

/// Minimum q_ema floor used in the negative-log cost to prevent ln(0).
const Q_EMA_FLOOR: f64 = 0.001;

/// Paths whose score >= SECONDARY_CONDUIT_THRESHOLD * best_score are retained
/// as secondary conduits.
///
/// secondary_conduit_threshold=0.85 is a Physarum-inspired retention policy:
/// keep near-competitive alternate channels visible instead of discarding them,
/// modelling the organism's tendency to preserve weak tubes under uncertainty.
/// Calibrated for Gate K.1; may be tuned as more topologies are validated.
const SECONDARY_CONDUIT_THRESHOLD: f64 = 0.85;

#[derive(Deserialize)]
pub struct PathsQuery {
    pub source: Option<String>,
    pub target: Option<String>,
    pub max_depth: Option<usize>,
}

pub async fn get_paths(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PathsQuery>,
) -> Response {
    let source = match query.source {
        Some(s) => s,
        None => {
            return (StatusCode::BAD_REQUEST, "missing query parameter: source").into_response()
        }
    };
    let target = match query.target {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_REQUEST, "missing query parameter: target").into_response()
        }
    };

    if source == target {
        return Json(PathsResponse {
            source,
            target,
            paths: vec![],
            selected_path: vec![],
            secondary_conduits: vec![],
        })
        .into_response();
    }

    let max_depth = query.max_depth.unwrap_or(5);
    let edges = state.edges.read().await;

    let mut found: Vec<PathResult> = Vec::new();
    let mut visited: HashSet<AgentId> = HashSet::new();
    visited.insert(source.clone());

    dfs(
        &source,
        &target,
        &edges,
        &mut visited,
        &mut Vec::new(),
        &mut found,
        max_depth,
    );

    found.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let selected_path = found.first().map(|p| p.nodes.clone()).unwrap_or_default();

    let best_score = found.first().map(|p| p.score).unwrap_or(0.0);
    let threshold = SECONDARY_CONDUIT_THRESHOLD * best_score;
    let secondary_conduits: Vec<PathResult> = found
        .iter()
        .skip(1)
        .filter(|p| p.score >= threshold)
        .cloned()
        .collect();

    Json(PathsResponse {
        source,
        target,
        paths: found,
        selected_path,
        secondary_conduits,
    })
    .into_response()
}

/// Compute the negative-log path score from a slice of path edges.
///
/// score = exp(-(sum(-ln(max(q_ema, Q_EMA_FLOOR))) + HOP_WEIGHT * (hops - 1)))
///
/// Weak edges (low q_ema) dominate the cost, matching Physarum resistance semantics.
/// The hop penalty is a small structural cost per additional edge beyond the first.
pub fn path_score(edges: &[PathEdge]) -> f64 {
    if edges.is_empty() {
        return 0.0;
    }
    let edge_cost: f64 = edges
        .iter()
        .map(|e| -(e.q_ema.max(Q_EMA_FLOOR).ln()))
        .sum();
    let hop_penalty = HOP_WEIGHT * (edges.len() - 1) as f64;
    (-(edge_cost + hop_penalty)).exp()
}

fn dfs(
    current: &str,
    target: &str,
    edges: &HashMap<(AgentId, AgentId), EdgeSnapshot>,
    visited: &mut HashSet<AgentId>,
    path_edges: &mut Vec<PathEdge>,
    results: &mut Vec<PathResult>,
    remaining_depth: usize,
) {
    if current == target {
        let mut nodes: Vec<AgentId> = path_edges.iter().map(|e| e.source.clone()).collect();
        nodes.push(target.to_string());
        let hops = path_edges.len();
        let score = path_score(path_edges);
        results.push(PathResult {
            nodes,
            edges: path_edges.clone(),
            score,
            hops,
        });
        return;
    }

    if remaining_depth == 0 {
        return;
    }

    for ((src, dst), edge) in edges.iter() {
        if src == current && !visited.contains(dst.as_str()) {
            visited.insert(dst.clone());
            path_edges.push(PathEdge {
                source: src.clone(),
                target: dst.clone(),
                d_ij: edge.d_ij,
                q_ema: edge.q_ema,
            });
            dfs(
                dst,
                target,
                edges,
                visited,
                path_edges,
                results,
                remaining_depth - 1,
            );
            path_edges.pop();
            visited.remove(dst.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(q_ema: f64) -> PathEdge {
        PathEdge {
            source: "a".to_string(),
            target: "b".to_string(),
            d_ij: 0.833,
            q_ema,
        }
    }

    #[test]
    fn single_healthy_edge_scores_near_one() {
        let e = vec![edge(0.9999)];
        let s = path_score(&e);
        assert!(s > 0.99, "healthy single-hop score should be near 1, got {s}");
    }

    #[test]
    fn empty_edges_score_zero() {
        assert_eq!(path_score(&[]), 0.0);
    }

    #[test]
    fn degraded_direct_loses_to_healthy_indirect() {
        // Direct path B->E: 1 edge, q_ema degraded to 0.8524 (Gate K tc/netem observed value)
        let direct = vec![edge(0.8524)];
        // Indirect path B->C->D->E: 3 edges all healthy
        let indirect = vec![edge(0.9997), edge(0.9997), edge(0.9998)];

        let score_direct = path_score(&direct);
        let score_indirect = path_score(&indirect);

        assert!(
            score_indirect > score_direct,
            "healthy indirect (score={score_indirect:.4}) should beat degraded direct (score={score_direct:.4})"
        );
    }

    #[test]
    fn healthy_direct_beats_healthy_indirect() {
        // Direct path: 1 edge, fully healthy
        let direct = vec![edge(0.9999)];
        // Indirect path: 3 edges, fully healthy
        let indirect = vec![edge(0.9997), edge(0.9997), edge(0.9998)];

        let score_direct = path_score(&direct);
        let score_indirect = path_score(&indirect);

        assert!(
            score_direct > score_indirect,
            "healthy direct (score={score_direct:.4}) should beat healthy indirect (score={score_indirect:.4})"
        );
    }

    #[test]
    fn secondary_conduit_threshold_retains_near_tie() {
        // best score ≈ 0.9999; alternate at 0.90 (0.90 / 0.9999 ≈ 0.90 >= 0.85)
        let best = path_score(&[edge(0.9999)]);
        let alternate_score = 0.90_f64;
        assert!(
            alternate_score >= SECONDARY_CONDUIT_THRESHOLD * best,
            "path at 0.90 should be retained as secondary conduit (threshold={:.3})",
            SECONDARY_CONDUIT_THRESHOLD * best
        );
    }

    #[test]
    fn secondary_conduit_threshold_drops_distant_path() {
        // best score ≈ 0.9999; alternate at 0.50 (0.50 / 0.9999 ≈ 0.50 < 0.85)
        let best = path_score(&[edge(0.9999)]);
        let distant_score = 0.50_f64;
        assert!(
            distant_score < SECONDARY_CONDUIT_THRESHOLD * best,
            "path at 0.50 should NOT be retained as secondary conduit"
        );
    }
}

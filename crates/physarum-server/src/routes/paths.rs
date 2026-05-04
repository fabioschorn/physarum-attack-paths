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

    Json(PathsResponse {
        source,
        target,
        paths: found,
    })
    .into_response()
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
        let score: f64 = path_edges.iter().map(|e| e.d_ij).product();
        results.push(PathResult {
            nodes,
            edges: path_edges.clone(),
            score,
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

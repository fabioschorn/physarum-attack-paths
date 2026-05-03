use axum::{extract::State, http::StatusCode, Json};
use physarum_protocol::{EdgeSnapshot, ProbeReport};
use std::sync::Arc;

use crate::state::AppState;

const DECAY_RATE: f64 = 0.1;

/// Physarum flux function: f(Q) = Q² / (1 + Q²)
fn flux(q: f64) -> f64 {
    (q * q) / (1.0 + q * q)
}

/// D_ij(t + Δt) = D_ij(t) + f(Q) · (1 − D_ij) − r · D_ij, clamped to [0.0, 1.0].
pub(crate) fn update_conductivity(current: f64, success: bool) -> f64 {
    let q = if success { 1.0 } else { 0.0 };
    let delta = flux(q) * (1.0 - current) - DECAY_RATE * current;
    (current + delta).clamp(0.0, 1.0)
}

pub async fn ingest_report(
    State(state): State<Arc<AppState>>,
    Json(report): Json<ProbeReport>,
) -> StatusCode {
    let key = (report.source.clone(), report.target.clone());
    let mut edges = state.edges.write().await;

    let edge = edges.entry(key).or_insert_with(|| EdgeSnapshot {
        source: report.source.clone(),
        target: report.target.clone(),
        probe_success: report.success,
        d_ij: 0.0,
        last_seen: report.observed_at,
    });

    edge.d_ij = update_conductivity(edge.d_ij, report.success);
    edge.probe_success = report.success;
    edge.last_seen = report.observed_at;

    tracing::info!(
        source = %report.source,
        target = %report.target,
        success = %report.success,
        d_ij = %edge.d_ij,
        "probe report ingested"
    );

    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_increases_d_ij() {
        let d0 = 0.0_f64;
        let d1 = update_conductivity(d0, true);
        assert!(d1 > d0, "D_ij should increase after success: {d0} -> {d1}");
    }

    #[test]
    fn failure_decreases_d_ij() {
        let d0 = 0.5_f64;
        let d1 = update_conductivity(d0, false);
        assert!(d1 < d0, "D_ij should decrease after failure: {d0} -> {d1}");
    }

    #[test]
    fn d_ij_never_exceeds_one() {
        let mut d = 0.0_f64;
        for _ in 0..1_000 {
            d = update_conductivity(d, true);
        }
        assert!(d <= 1.0, "D_ij exceeded 1.0: got {d}");
    }

    #[test]
    fn d_ij_never_below_zero() {
        let mut d = 0.5_f64;
        for _ in 0..1_000 {
            d = update_conductivity(d, false);
        }
        assert!(d >= 0.0, "D_ij went below 0.0: got {d}");
    }

    #[test]
    fn failure_exact_decay() {
        // f(0) = 0  →  D(t+1) = D(t) - r·D(t) = D(t)·(1 - r)
        let d0 = 0.5_f64;
        let d1 = update_conductivity(d0, false);
        let expected = (d0 * (1.0 - DECAY_RATE)).clamp(0.0, 1.0);
        assert!((d1 - expected).abs() < 1e-12, "expected {expected}, got {d1}");
    }

    #[test]
    fn success_exact_step_from_zero() {
        // f(1) = 0.5  →  D(t+1) = 0 + 0.5·(1-0) - 0.1·0 = 0.5
        let d1 = update_conductivity(0.0, true);
        let expected = 0.5_f64;
        assert!((d1 - expected).abs() < 1e-12, "expected {expected}, got {d1}");
    }

    #[test]
    fn converges_below_one_under_continuous_success() {
        // Stable equilibrium for Q=1 is D* = 5/6 ≈ 0.833, never reaches 1.0.
        let mut d = 0.0_f64;
        for _ in 0..10_000 {
            d = update_conductivity(d, true);
        }
        assert!(d < 1.0, "D_ij should converge below 1.0: got {d}");
        assert!(d > 0.8, "D_ij should converge above 0.8: got {d}");
    }
}

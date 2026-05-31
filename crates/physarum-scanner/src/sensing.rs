/// Organism-native sensing layer for `physarum-scanner` (Issue #114).
///
/// Evolves the scanner from "host + open port" toward structured evidence
/// that can feed `physarum-llm` `DiscoveryQuery` directly.
///
/// # Design philosophy
///
/// Classic scan flags (`-T4`, `-F`, `-Pn`) are useful inspiration but must not
/// become permanent CLI-parity features. Instead they are encoded as organism-
/// native `SensingProfile` variants. The organism chooses how sensitive it needs
/// to be based on stimulus, scope, risk, and prior lineage memory.
///
/// # Relationship to Issue #106
///
/// `SensingResult` is shaped to populate `physarum_llm::DiscoveryQuery` fields:
///
/// | SensingResult field              | DiscoveryQuery field         |
/// |----------------------------------|------------------------------|
/// | `port` + `protocol` + `state`    | `ports[].port/protocol/state` |
/// | `service_guess`                  | `ports[].service_guess`      |
/// | `banner_or_handshake_summary`    | `ports[].banner`             |
/// | `version_hint`                   | `ports[].version_hint`       |
/// | `os_hint`                        | `os_hint`                    |
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

// ── SensingProfile ─────────────────────────────────────────────────────────

/// Organism-native sensing intensity profile.
///
/// Maps to scanner parameters (batch_size, timeout, port subset) in a
/// deterministic, policy-checkable way. The organism picks the profile
/// based on stimulus type, lineage scope, and risk context — not on
/// raw CLI flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensingProfile {
    /// Low concurrency, long timeouts, small port scope.
    /// Conservative expansion — used when noise budget is tight.
    LowNoise,

    /// Moderate concurrency, standard timeout, broad service ports.
    /// Good default for lab exploration and periodic subnet discovery.
    Balanced,

    /// Higher bounded concurrency, shorter timeout, top-service port subset.
    /// Inspired by `-T4` — useful when speed matters and scope is trusted.
    /// Port subset: see [`TOP_PORTS`].
    Fast,

    /// Same port subset as `Fast` but at moderate concurrency and longer timeout.
    /// Inspired by `-F` — top-service coverage without aggressive timing.
    /// Use when completeness of the `TOP_PORTS` set matters more than raw speed.
    TopPorts,

    /// Richer service characterization: banner collection, larger port set.
    /// Slower but produces better evidence for LLM reasoning.
    Deep,

    /// Exact /32 host already captured by TCP/ICMP/eBPF/packet/lineage stimulus.
    /// Full service probe on that single host — best evidence density.
    /// Inspired by capturing a stimulated host directly.
    StimulusTargeted,

    /// Do not depend on ICMP host discovery.
    /// Treat host as alive when already evidenced by TCP, eBPF, packet
    /// observation, lineage, or previous probe. Inspired by `-Pn`.
    /// Only applies when the host is already evidenced — not a blanket flag.
    NoDiscovery,
}

/// Scanner parameters derived from a `SensingProfile`.
#[derive(Debug, Clone)]
pub struct ProfileParams {
    pub batch_size: usize,
    pub timeout_ms: u64,
    pub tries: u8,
    /// Port subset to scan. `None` means use the caller's port list unchanged.
    pub port_subset: Option<&'static [u16]>,
    /// When true the scanner skips ICMP host-up check and treats the host as alive.
    pub skip_host_discovery: bool,
}

impl SensingProfile {
    /// Returns the deterministic scanner parameters for this profile.
    pub fn params(&self) -> ProfileParams {
        match self {
            Self::LowNoise => ProfileParams {
                batch_size: 100,
                timeout_ms: 5_000,
                tries: 2,
                port_subset: Some(TOP_PORTS),
                skip_host_discovery: false,
            },
            Self::Balanced => ProfileParams {
                batch_size: 500,
                timeout_ms: 3_000,
                tries: 1,
                port_subset: None,
                skip_host_discovery: false,
            },
            Self::Fast => ProfileParams {
                batch_size: 2_000,
                timeout_ms: 1_000,
                tries: 1,
                port_subset: Some(TOP_PORTS),
                skip_host_discovery: false,
            },
            Self::TopPorts => ProfileParams {
                batch_size: 1_000,
                timeout_ms: 2_000,
                tries: 1,
                port_subset: Some(TOP_PORTS),
                skip_host_discovery: false,
            },
            Self::Deep => ProfileParams {
                batch_size: 300,
                timeout_ms: 4_000,
                tries: 2,
                port_subset: Some(DEEP_PORTS),
                skip_host_discovery: false,
            },
            Self::StimulusTargeted => ProfileParams {
                batch_size: 200,
                timeout_ms: 2_000,
                tries: 2,
                port_subset: Some(STIMULUS_PORTS),
                skip_host_discovery: true,
            },
            Self::NoDiscovery => ProfileParams {
                batch_size: 500,
                timeout_ms: 3_000,
                tries: 1,
                port_subset: None,
                skip_host_discovery: true,
            },
        }
    }

    /// Returns true when the profile suppresses ICMP host-up discovery.
    pub fn skips_host_discovery(&self) -> bool {
        self.params().skip_host_discovery
    }
}

// ── Port subsets ──────────────────────────────────────────────────────────────

/// Top service ports — used by `Fast` and `LowNoise` profiles.
///
/// Inspired by `-F` (top-100 in nmap), but bounded to the services most
/// relevant to organism propagation paths. Not a permanent hard-coded list —
/// this set should evolve as the organism's threat model matures.
pub const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080,
];

/// Extended port set for `Deep` profile — broader service characterization.
pub const DEEP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 631, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 4243, 5000, 5432, 5900, 5984, 6379,
    6443, 7001, 7080, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 9443, 9999,
];

/// Focused port set for `StimulusTargeted` — stimulus host service probe.
///
/// 7777 is included as a representative non-standard web-service port with no
/// registered service name. It exercises the `UnknownNeedsMoreSensing → HTTP
/// probe → ConfirmedWeb` adaptive fingerprint path (PF-3.1 validation).
pub const STIMULUS_PORTS: &[u16] = &[22, 80, 443, 7777, 8080, 8443, 3000, 5000, 9000];

// ── SchemeHint / NextProbeHint ────────────────────────────────────────────────

/// Protocol scheme inferred from banner evidence or port convention.
///
/// Used by physarum-maze to select HTTP/HTTPS probe strategy and by
/// `PatternRunner` to avoid scheme mis-detection on non-standard ports.
/// Starts as `Unknown` (port-convention only); upgraded to `Http`/`Https`
/// after banner confirmation in the adaptive fingerprint pass (PF-3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SchemeHint {
    Http,
    Https,
    #[default]
    Unknown,
}

/// Next sensing action recommended when protocol evidence is insufficient.
///
/// Set initially from port convention by [`result_from_open_port`].
/// Cleared (`None`) once banner grab or HTTP probe resolves the ambiguity.
/// Consumed by physarum-maze's adaptive re-sensing loop (PF-3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NextProbeHint {
    /// Send an HTTP or HTTPS probe to resolve protocol ambiguity.
    HttpProbe { scheme: SchemeHint },
    /// No additional probing recommended for this service.
    None,
}

// ── SensingResult ─────────────────────────────────────────────────────────────

/// Structured evidence produced by the sensing layer.
///
/// Richer than a raw `SocketAddr` — shaped to populate
/// `physarum_llm::DiscoveryQuery` without any extra transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensingResult {
    pub target_ip: IpAddr,
    pub port: u16,
    pub protocol: TransportProtocol,
    pub profile: SensingProfile,
    pub state: PortState,
    /// Best-effort service name derived from port number and banner.
    pub service_guess: Option<String>,
    /// First ≤ 256 bytes of the banner or handshake, sanitised.
    /// Never raw binary. `None` if the connection returned no readable data.
    pub banner_or_handshake_summary: Option<String>,
    /// Version string parsed from the banner, if recognisable.
    pub version_hint: Option<String>,
    /// Best-effort OS hint derived from banner/convention only.
    /// No raw sockets or CAP_NET_RAW required.
    pub os_hint: Option<OsHint>,
    /// Confidence in the evidence (0.0–1.0). Port-number-only evidence scores
    /// lower than banner-confirmed evidence.
    pub confidence: f32,
    pub evidence_source: EvidenceSource,
    /// Protocol scheme derived from port convention or banner evidence.
    /// Starts as `Unknown`; upgraded to `Http`/`Https` after banner grab.
    pub scheme_hint: SchemeHint,
    /// Next sensing action recommended when evidence remains ambiguous.
    /// Cleared once banner grab or HTTP probe resolves the service class.
    pub recommended_next_probe: NextProbeHint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

/// How this evidence was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// Periodic /24 TCP-connect subnet discovery.
    ScheduledScan,
    /// Inbound TCP SYN to port 22 — host actively signalled.
    TcpStimulus,
    /// Inbound ICMP echo request — host actively signalled.
    IcmpStimulus,
    /// eBPF ring-buffer observation of an inbound connection.
    EbpfObservation,
    /// Raw packet observation (tc ingress) of ICMP/TCP.
    PacketObservation,
    /// Re-derived from an existing lineage record — not a new scan.
    LineageMemory,
    /// Manually seeded in a lab scenario.
    ManualLabSeed,
}

// ── OsHint ────────────────────────────────────────────────────────────────────

/// Best-effort OS hint — no raw sockets required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsHint {
    pub guess: String,
    pub confidence: f32,
    pub source: OsHintSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsHintSource {
    SshBanner,
    HttpHeader,
    ServiceBanner,
    Convention,
}

// ── Scheme + probe hint derivation ───────────────────────────────────────────

/// Infer protocol scheme from port convention alone.
///
/// Returns `Https` for well-known TLS ports, `Http` for well-known plain-HTTP
/// ports, and `Unknown` for everything else. Callers should upgrade this after
/// a banner grab confirms the actual scheme.
fn scheme_hint_from_port(port: u16) -> SchemeHint {
    match port {
        443 | 8443 | 9443 => SchemeHint::Https,
        80 | 2375 | 2376 | 3000 | 4243 | 5000 | 5984 | 7080 | 8000 | 8080 | 8888 | 9000 | 9090
        | 9200 | 9999 => SchemeHint::Http,
        _ => SchemeHint::Unknown,
    }
}

/// Recommend the next probe based on initial port + service_guess evidence.
///
/// Non-web protocols (SSH, SMTP, …) and well-known web ports need no further
/// probing — the organism already knows enough to classify the service.
/// Unknown ports with no conclusive service_guess get `HttpProbe` so the
/// maze's adaptive fingerprint pass can resolve the ambiguity.
fn initial_probe_hint(service_guess: &Option<String>, scheme_hint: &SchemeHint) -> NextProbeHint {
    if let Some(g) = service_guess {
        let g_lower = g.to_ascii_lowercase();
        // Definitively non-web protocols — HTTP probe would be meaningless.
        if matches!(
            g_lower.as_str(),
            "ssh"
                | "ftp"
                | "sftp"
                | "telnet"
                | "smtp"
                | "smtps"
                | "submission"
                | "pop3"
                | "pop3s"
                | "imap"
                | "imaps"
                | "mysql"
                | "postgresql"
                | "redis"
                | "mssql"
                | "oracle"
                | "ldap"
                | "ldaps"
                | "rdp"
                | "vnc"
                | "netbios-ssn"
                | "microsoft-ds"
                | "syslog"
                | "dns"
                | "rpcbind"
                | "ipp"
                | "nfs"
                | "socks"
                | "pptp"
        ) {
            return NextProbeHint::None;
        }
    }
    // Well-known web port — scheme is already determined by convention.
    if !matches!(scheme_hint, SchemeHint::Unknown) {
        return NextProbeHint::None;
    }
    // Unknown scheme and no conclusive service_guess — recommend HTTP probe.
    NextProbeHint::HttpProbe {
        scheme: SchemeHint::Unknown,
    }
}

// ── Service guess ─────────────────────────────────────────────────────────────

/// Best-effort service name from port number alone.
///
/// Scores a confidence of 0.5 — port-convention only, not banner-confirmed.
/// Banner-confirmed service guesses score higher (set by the caller).
pub fn service_guess_from_port(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        135 => Some("msrpc"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        465 => Some("smtps"),
        514 => Some("syslog"),
        587 => Some("submission"),
        631 => Some("ipp"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1080 => Some("socks"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        2375 | 2376 => Some("docker"),
        3000 => Some("http-dev"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        4243 => Some("docker"),
        5000 => Some("http-dev"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        5984 => Some("couchdb"),
        6379 => Some("redis"),
        6443 => Some("kubernetes"),
        7001 => Some("weblogic"),
        7080 | 8000 | 8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        8888 => Some("http-dev"),
        9000 => Some("http-dev"),
        9090 => Some("http-dev"),
        9200 => Some("elasticsearch"),
        9300 => Some("elasticsearch"),
        9443 => Some("https-alt"),
        9999 => Some("http-dev"),
        _ => None,
    }
}

/// Build a `SensingResult` from a raw open-port observation (no banner).
///
/// Sets `confidence = 0.5` — port-convention only.
/// Sets `scheme_hint` and `recommended_next_probe` from port convention.
/// The caller can upgrade all three after banner collection.
pub fn result_from_open_port(
    target_ip: IpAddr,
    port: u16,
    profile: SensingProfile,
    evidence_source: EvidenceSource,
) -> SensingResult {
    let service_guess = service_guess_from_port(port).map(|s| s.to_string());
    let os_hint = infer_os_hint_from_port(port);
    let scheme_hint = scheme_hint_from_port(port);
    let recommended_next_probe = initial_probe_hint(&service_guess, &scheme_hint);

    SensingResult {
        target_ip,
        port,
        protocol: TransportProtocol::Tcp,
        profile,
        state: PortState::Open,
        service_guess,
        banner_or_handshake_summary: None,
        version_hint: None,
        os_hint,
        confidence: 0.5,
        evidence_source,
        scheme_hint,
        recommended_next_probe,
    }
}

/// Infer a weak OS hint from port number and convention only.
/// No banner required — confidence is intentionally low.
fn infer_os_hint_from_port(port: u16) -> Option<OsHint> {
    match port {
        3389 => Some(OsHint {
            guess: "Windows".into(),
            confidence: 0.5,
            source: OsHintSource::Convention,
        }),
        22 => Some(OsHint {
            guess: "Linux/Unix".into(),
            confidence: 0.4,
            source: OsHintSource::Convention,
        }),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_params_are_deterministic() {
        let p1 = SensingProfile::Fast.params();
        let p2 = SensingProfile::Fast.params();
        assert_eq!(p1.batch_size, p2.batch_size);
        assert_eq!(p1.timeout_ms, p2.timeout_ms);
    }

    #[test]
    fn fast_profile_uses_top_ports_subset() {
        let params = SensingProfile::Fast.params();
        let subset = params.port_subset.expect("Fast must have a port subset");
        assert!(!subset.is_empty());
        // Port 80 and 22 must be in the fast subset
        assert!(subset.contains(&80), "port 80 must be in TOP_PORTS");
        assert!(subset.contains(&22), "port 22 must be in TOP_PORTS");
    }

    #[test]
    fn balanced_profile_uses_caller_port_list() {
        let params = SensingProfile::Balanced.params();
        assert!(
            params.port_subset.is_none(),
            "Balanced must not restrict port list"
        );
    }

    #[test]
    fn no_discovery_skips_host_discovery() {
        assert!(SensingProfile::NoDiscovery.skips_host_discovery());
        assert!(SensingProfile::StimulusTargeted.skips_host_discovery());
        assert!(!SensingProfile::Balanced.skips_host_discovery());
        assert!(!SensingProfile::Fast.skips_host_discovery());
    }

    #[test]
    fn deep_profile_has_more_ports_than_fast() {
        let fast_ports = SensingProfile::Fast.params().port_subset.unwrap();
        let deep_ports = SensingProfile::Deep.params().port_subset.unwrap();
        assert!(
            deep_ports.len() > fast_ports.len(),
            "Deep must probe more ports than Fast"
        );
    }

    #[test]
    fn service_guess_known_ports() {
        assert_eq!(service_guess_from_port(22), Some("ssh"));
        assert_eq!(service_guess_from_port(80), Some("http"));
        assert_eq!(service_guess_from_port(443), Some("https"));
        assert_eq!(service_guess_from_port(3306), Some("mysql"));
        assert_eq!(service_guess_from_port(3389), Some("rdp"));
        assert_eq!(service_guess_from_port(6379), Some("redis"));
        assert_eq!(service_guess_from_port(9999), Some("http-dev"));
    }

    #[test]
    fn service_guess_unknown_port_returns_none() {
        assert_eq!(service_guess_from_port(12345), None);
        assert_eq!(service_guess_from_port(0), None);
    }

    #[test]
    fn result_from_open_port_sets_correct_fields() {
        use std::net::IpAddr;
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let result =
            result_from_open_port(ip, 80, SensingProfile::Fast, EvidenceSource::ScheduledScan);
        assert_eq!(result.port, 80);
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.service_guess.as_deref(), Some("http"));
        assert_eq!(result.confidence, 0.5);
        assert!(result.banner_or_handshake_summary.is_none());
    }

    #[test]
    fn sensing_result_round_trips_json() {
        use std::net::IpAddr;
        let ip: IpAddr = "172.20.0.3".parse().unwrap();
        let result = SensingResult {
            target_ip: ip,
            port: 443,
            protocol: TransportProtocol::Tcp,
            profile: SensingProfile::Deep,
            state: PortState::Open,
            service_guess: Some("https".into()),
            banner_or_handshake_summary: Some("TLSv1.3".into()),
            version_hint: Some("nginx/1.25".into()),
            os_hint: Some(OsHint {
                guess: "Linux".into(),
                confidence: 0.7,
                source: OsHintSource::HttpHeader,
            }),
            confidence: 0.85,
            evidence_source: EvidenceSource::EbpfObservation,
            scheme_hint: SchemeHint::Https,
            recommended_next_probe: NextProbeHint::None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: SensingResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.port, 443);
        assert_eq!(back.service_guess.as_deref(), Some("https"));
        assert_eq!(back.version_hint.as_deref(), Some("nginx/1.25"));
        assert_eq!(back.scheme_hint, SchemeHint::Https);
        assert_eq!(back.recommended_next_probe, NextProbeHint::None);
    }

    #[test]
    fn result_from_open_port_derives_scheme_hint() {
        use std::net::IpAddr;
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let r80 =
            result_from_open_port(ip, 80, SensingProfile::Fast, EvidenceSource::ScheduledScan);
        assert_eq!(r80.scheme_hint, SchemeHint::Http);
        assert_eq!(r80.recommended_next_probe, NextProbeHint::None);

        let r443 =
            result_from_open_port(ip, 443, SensingProfile::Fast, EvidenceSource::ScheduledScan);
        assert_eq!(r443.scheme_hint, SchemeHint::Https);
        assert_eq!(r443.recommended_next_probe, NextProbeHint::None);

        // SSH — known non-web, no HTTP probe recommended
        let r22 =
            result_from_open_port(ip, 22, SensingProfile::Fast, EvidenceSource::ScheduledScan);
        assert_eq!(r22.scheme_hint, SchemeHint::Unknown);
        assert_eq!(r22.recommended_next_probe, NextProbeHint::None);

        // Unknown port — HTTP probe recommended to resolve ambiguity
        let r12345 = result_from_open_port(
            ip,
            12345,
            SensingProfile::Fast,
            EvidenceSource::ScheduledScan,
        );
        assert_eq!(r12345.scheme_hint, SchemeHint::Unknown);
        assert!(matches!(
            r12345.recommended_next_probe,
            NextProbeHint::HttpProbe { .. }
        ));
    }

    #[test]
    fn top_ports_profile_uses_top_ports_subset() {
        let params = SensingProfile::TopPorts.params();
        let subset = params
            .port_subset
            .expect("TopPorts must have a port subset");
        assert!(subset.contains(&22), "port 22 must be in TopPorts subset");
        assert!(subset.contains(&80), "port 80 must be in TopPorts subset");
        assert!(
            !params.skip_host_discovery,
            "TopPorts must not skip host discovery"
        );
        // TopPorts: slower than Fast (lower batch_size) but same port coverage
        assert!(params.batch_size < SensingProfile::Fast.params().batch_size);
        assert!(params.timeout_ms > SensingProfile::Fast.params().timeout_ms);
    }

    #[test]
    fn all_profiles_have_nonzero_batch_size_and_timeout() {
        for profile in [
            SensingProfile::LowNoise,
            SensingProfile::Balanced,
            SensingProfile::Fast,
            SensingProfile::TopPorts,
            SensingProfile::Deep,
            SensingProfile::StimulusTargeted,
            SensingProfile::NoDiscovery,
        ] {
            let p = profile.params();
            assert!(p.batch_size > 0, "{profile:?}: batch_size must be > 0");
            assert!(p.timeout_ms > 0, "{profile:?}: timeout_ms must be > 0");
        }
    }

    #[test]
    fn top_ports_contains_no_duplicates() {
        let mut sorted = TOP_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), TOP_PORTS.len(), "TOP_PORTS has duplicates");
    }

    #[test]
    fn os_hint_windows_from_rdp_port() {
        let hint = infer_os_hint_from_port(3389).unwrap();
        assert_eq!(hint.guess, "Windows");
        assert_eq!(hint.source, OsHintSource::Convention);
    }
}

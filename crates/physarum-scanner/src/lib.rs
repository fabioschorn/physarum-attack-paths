//! Full-featured async port scanner — a complete port of RustScan's feature set
//! onto the tokio executor, with improvements throughout.
//!
//! # Feature parity with RustScan
//!
//! | RustScan module          | physarum-scanner module       | Notes |
//! |--------------------------|-------------------------------|-------|
//! | `scanner/mod.rs`         | [`scanner`]                   | TCP + UDP, port exclusion |
//! | `scanner/socket_iterator`| [`socket_iterator`] (pub(crate)) | memory-efficient cartesian product |
//! | `port_strategy/mod.rs`   | [`port_strategy`]             | Serial, Random (LCG), Manual |
//! | `port_strategy/range_iterator` | [`range_iterator`] (pub(crate)) | LCG iterator |
//! | `address.rs`             | [`address`]                   | IP, CIDR, DNS, file, exclusions |
//! | `input.rs` (Config)      | [`config`]                    | TOML config + ScanConfig builder |
//! | `scripts/mod.rs`         | [`scripts`]                   | Nmap default + custom scripts |
//! | `benchmark/mod.rs`       | [`benchmark`]                 | named scan timers |
//! | `tui.rs`                 | [`output`]                    | warning!/detail!/output! macros |
//! | `main.rs` (ulimit)       | [`rlimit`]                    | RLIMIT_NOFILE management |
//! | `build.rs` (nmap-payloads) | [`nmap_payloads`]           | UDP payload DB, embedded via `include_str!` |
//!
//! # Key improvements over RustScan
//!
//! - **Tokio** executor throughout (no async-std dependency).
//! - **Typed errors** (`ScanError`) instead of `assert!`-on-error panics.
//! - **`SocketIterator`** replaces the pre-allocated `Vec<SocketAddr>` — zero
//!   allocation overhead for large IP × port products.
//! - **UDP payload map** is embedded at compile time (`include_str!`) and parsed
//!   lazily — no `build.rs` code generation required.  Callers can override
//!   with [`scanner::Scanner::udp_payloads`] for custom probes.
//! - **`ScanConfig`** struct lets library users compose scan parameters without
//!   a Clap dependency.
//! - **`rlimit`** module exposed as a plain function so library users can tune
//!   the FD limit before choosing `batch_size`.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use physarum_scanner::{Scanner, PortList};
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let ips = vec!["10.60.0.0/24".parse::<IpAddr>().unwrap()];
//!     let ports = PortList::explicit(vec![22, 80, 443, 8080]);
//!     let open = Scanner::new(ips, ports)
//!         .batch_size(500)
//!         .timeout_ms(1_500)
//!         .exclude_ports(vec![80])
//!         .run()
//!         .await
//!         .unwrap();
//!     for socket in open {
//!         println!("open: {socket}");
//!     }
//! }
//! ```

pub mod address;
pub mod benchmark;
pub mod config;
pub mod error;
pub mod nmap_payloads;
pub mod output;
pub mod port_strategy;
pub mod rlimit;
pub mod scanner;
pub mod scripts;
pub mod sensing;

pub(crate) mod range_iterator;
pub(crate) mod socket_iterator;

pub use error::ScanError;
pub use scanner::{ScanResult, Scanner};
pub use sensing::{
    result_from_open_port, service_guess_from_port, EvidenceSource, OsHint, OsHintSource,
    PortState, ProfileParams, SensingProfile, SensingResult, TransportProtocol, DEEP_PORTS,
    STIMULUS_PORTS, TOP_PORTS,
};

/// Explicit list of ports to scan.
///
/// Constructed via [`PortList::explicit`]; deduplicates and sorts on creation.
#[derive(Debug, Clone)]
pub struct PortList(Vec<u16>);

impl PortList {
    /// Build from an explicit list. Deduplicates and sorts ascending.
    pub fn explicit(mut ports: Vec<u16>) -> Self {
        ports.sort_unstable();
        ports.dedup();
        Self(ports)
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }
}

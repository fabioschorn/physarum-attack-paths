//! Async TCP connect port scanner for physarum candidate discovery.
//!
//! Inspired by [RustScan](https://github.com/RustScan/RustScan)'s high-level TCP-connect
//! discovery approach. Implemented independently in native tokio for physarum-agent;
//! no code was copied from RustScan.
//!
//! Key differences from RustScan:
//! - Pure tokio executor (no async-std dependency)
//! - Typed `Result` error propagation instead of `assert!`-on-error
//! - TCP-connect subset only — no UDP, no Nmap scripts, no TUI, no rlimit manipulation
//! - Hermetic tests (no Internet-facing targets)
//!
//! ## Example
//!
//! ```rust,no_run
//! use physarum_scanner::{Scanner, PortList};
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let ips = vec!["10.50.20.10".parse::<IpAddr>().unwrap()];
//!     let ports = PortList::explicit(vec![9001, 9002, 9003]);
//!     let open = Scanner::new(ips, ports)
//!         .batch_size(500)
//!         .timeout_ms(1_500)
//!         .run()
//!         .await
//!         .unwrap();
//!     println!("open sockets: {:?}", open);
//! }
//! ```

pub mod error;
pub mod scanner;

pub use error::ScanError;
pub use scanner::{ScanResult, Scanner};

/// Explicit list of ports to scan.
#[derive(Debug, Clone)]
pub struct PortList(Vec<u16>);

impl PortList {
    /// Construct from an explicit list. Deduplicates and sorts.
    pub fn explicit(mut ports: Vec<u16>) -> Self {
        ports.sort_unstable();
        ports.dedup();
        Self(ports)
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }
}

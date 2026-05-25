//! TOML configuration file support.
//!
//! Ported from RustScan's `input.rs` (Config + Opts merge logic) and improved:
//! - Errors are logged via `tracing` instead of `println!` + `process::exit`.
//! - Missing config file silently returns `Config::default()`.
//! - `merge_into` applies config values onto a `ScanConfig` struct (no Clap dep).

use crate::port_strategy::{PortRange, ScanOrder};
use crate::scripts::ScriptsRequired;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// Scanner parameters loaded from a TOML file.
///
/// All fields are `Option<T>` — only specified fields override scanner defaults.
///
/// Default config path (tried in order):
/// 1. `$XDG_CONFIG_HOME/.rustscan.toml` (or `~/.config/.rustscan.toml`)
/// 2. `~/.rustscan.toml` (legacy path)
///
/// Example config:
/// ```toml
/// batch_size  = 5000
/// timeout     = 1500
/// tries       = 1
/// scan_order  = "Random"
/// scripts     = "none"
/// exclude_ports = [22, 80]
/// ```
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub addresses: Option<Vec<String>>,
    pub ports: Option<Vec<u16>>,
    pub range: Option<PortRange>,
    pub greppable: Option<bool>,
    pub accessible: Option<bool>,
    pub batch_size: Option<usize>,
    pub timeout: Option<u32>,
    pub tries: Option<u8>,
    pub ulimit: Option<u64>,
    pub resolver: Option<String>,
    pub scan_order: Option<ScanOrder>,
    pub scripts: Option<ScriptsRequired>,
    pub command: Option<Vec<String>>,
    pub exclude_ports: Option<Vec<u16>>,
    pub exclude_addresses: Option<Vec<String>>,
    pub udp: Option<bool>,
    pub no_banner: Option<bool>,
}

impl Config {
    /// Read and deserialise the TOML config file.
    ///
    /// Resolution order:
    /// 1. `path` — explicit path override.
    /// 2. `$XDG_CONFIG_HOME/.rustscan.toml`
    /// 3. `~/.rustscan.toml`
    /// 4. (missing file) → `Config::default()`.
    pub fn read(path: Option<PathBuf>) -> Self {
        let resolved = path.unwrap_or_else(|| {
            let xdg_path = dirs::config_dir().map(|mut p| {
                p.push(".rustscan.toml");
                p
            });
            let home_path = dirs::home_dir().map(|mut p| {
                p.push(".rustscan.toml");
                p
            });
            xdg_path
                .filter(|p| p.exists())
                .or_else(|| home_path.filter(|p| p.exists()))
                .unwrap_or_default()
        });

        if !resolved.exists() {
            return Config::default();
        }

        let content = match fs::read_to_string(&resolved) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %resolved.display(),
                    err = %e,
                    "could not read config file — using defaults"
                );
                return Config::default();
            }
        };

        match toml::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    err = %e,
                    "invalid TOML in config file — using defaults"
                );
                Config::default()
            }
        }
    }
}

/// Flat scanner configuration that callers build and pass to [`Scanner`].
///
/// This mirrors what RustScan's `Opts` struct produced after merging CLI args
/// with the config file, but without a Clap dependency — callers compose it
/// directly or fill it from `Config::read()`.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub addresses: Vec<String>,
    pub ports: Option<Vec<u16>>,
    pub range: Option<PortRange>,
    pub exclude_ports: Vec<u16>,
    pub exclude_addresses: Option<Vec<String>>,
    pub batch_size: usize,
    pub timeout_ms: u32,
    pub tries: u8,
    pub ulimit: Option<u64>,
    pub resolver: Option<String>,
    pub scan_order: ScanOrder,
    pub scripts: ScriptsRequired,
    pub command: Vec<String>,
    pub greppable: bool,
    pub accessible: bool,
    pub udp: bool,
    pub no_banner: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: None,
            range: Some(PortRange::all()),
            exclude_ports: vec![],
            exclude_addresses: None,
            batch_size: 4_500,
            timeout_ms: 1_500,
            tries: 1,
            ulimit: None,
            resolver: None,
            scan_order: ScanOrder::Serial,
            scripts: ScriptsRequired::Default,
            command: vec![],
            greppable: false,
            accessible: false,
            udp: false,
            no_banner: false,
        }
    }
}

impl ScanConfig {
    /// Apply non-`None` values from `config`, overriding current fields.
    pub fn merge(&mut self, config: &Config) {
        if let Some(v) = &config.addresses {
            self.addresses = v.clone();
        }
        if let Some(v) = &config.ports {
            self.ports = Some(v.clone());
        }
        if let Some(v) = &config.range {
            self.range = Some(v.clone());
        }
        if let Some(v) = &config.exclude_ports {
            self.exclude_ports = v.clone();
        }
        if let Some(v) = &config.exclude_addresses {
            self.exclude_addresses = Some(v.clone());
        }
        if let Some(v) = config.batch_size {
            self.batch_size = v;
        }
        if let Some(v) = config.timeout {
            self.timeout_ms = v;
        }
        if let Some(v) = config.tries {
            self.tries = v;
        }
        if let Some(v) = config.ulimit {
            self.ulimit = Some(v);
        }
        if let Some(v) = &config.resolver {
            self.resolver = Some(v.clone());
        }
        if let Some(v) = config.scan_order {
            self.scan_order = v;
        }
        if let Some(v) = config.scripts {
            self.scripts = v;
        }
        if let Some(v) = &config.command {
            self.command = v.clone();
        }
        if let Some(v) = config.greppable {
            self.greppable = v;
        }
        if let Some(v) = config.accessible {
            self.accessible = v;
        }
        if let Some(v) = config.udp {
            self.udp = v;
        }
        if let Some(v) = config.no_banner {
            self.no_banner = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scan_config_sane() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.batch_size, 4_500);
        assert_eq!(cfg.timeout_ms, 1_500);
        assert_eq!(cfg.tries, 1);
        assert!(!cfg.udp);
    }

    #[test]
    fn merge_applies_non_none_fields() {
        let mut sc = ScanConfig::default();
        let config = Config {
            batch_size: Some(1000),
            timeout: Some(500),
            udp: Some(true),
            ..Default::default()
        };
        sc.merge(&config);
        assert_eq!(sc.batch_size, 1000);
        assert_eq!(sc.timeout_ms, 500);
        assert!(sc.udp);
        // unchanged
        assert_eq!(sc.tries, 1);
    }

    #[test]
    fn merge_none_fields_unchanged() {
        let mut sc = ScanConfig::default();
        let config = Config::default(); // all None
        sc.merge(&config);
        assert_eq!(sc.batch_size, 4_500);
    }

    #[test]
    fn config_from_toml_string() {
        let toml = r#"
            batch_size  = 2000
            timeout     = 800
            scan_order  = "Random"
            udp         = true
            exclude_ports = [22, 80, 443]
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.batch_size, Some(2000));
        assert_eq!(config.timeout, Some(800));
        assert_eq!(config.scan_order, Some(ScanOrder::Random));
        assert_eq!(config.udp, Some(true));
        assert_eq!(config.exclude_ports, Some(vec![22, 80, 443]));
    }

    #[test]
    fn missing_config_file_returns_default() {
        let cfg = Config::read(Some("/tmp/physarum-nonexistent-config-xyz.toml".into()));
        assert!(cfg.batch_size.is_none());
    }
}

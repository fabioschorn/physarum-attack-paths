//! Post-scan scripting engine.
//!
//! Ported from RustScan's `scripts/mod.rs` and improved:
//! - Template substitution is done with simple string replacement (no extra dep).
//! - `anyhow::Result` replaces panic on missing fields.
//! - `ScriptFile::into_script()` is the clean conversion path.
//! - Uses `tracing::debug!` instead of `log::debug!`.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tracing::debug;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

/// Which post-scan scripts to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptsRequired {
    /// No post-scan scripts — port results only.
    None,
    /// Built-in Nmap script: `nmap -vvv -p <ports> -4/-6 <ip>`.
    #[default]
    Default,
    /// Load scripts from `~/.rustscan_scripts/` filtered by tags in
    /// `~/.rustscan_scripts.toml`.
    Custom,
}

/// Built-in default script (Nmap).
const DEFAULT_SCRIPT_TOML: &str = r#"tags = ["core_approved", "default"]
developer = ["physarum"]
ports_separator = ","
call_format = "nmap -vvv -p {{port}} -{{ipversion}} {{ip}}"
"#;

/// Return the list of scripts to run for the given mode.
///
/// - `None`    → empty list.
/// - `Default` → single built-in Nmap script.
/// - `Custom`  → scripts from `~/.rustscan_scripts/` filtered by config tags.
pub fn init_scripts(mode: ScriptsRequired) -> Result<Vec<ScriptFile>> {
    match mode {
        ScriptsRequired::None => Ok(vec![]),

        ScriptsRequired::Default => {
            let sf = toml::from_str::<ScriptFile>(DEFAULT_SCRIPT_TOML)
                .map_err(|e| anyhow!("failed to parse built-in script: {e}"))?;
            Ok(vec![sf])
        }

        ScriptsRequired::Custom => {
            let cfg = ScriptConfig::read()?;
            let dir = cfg
                .directory
                .as_deref()
                .map(PathBuf::from)
                .or_else(dirs::home_dir)
                .ok_or_else(|| anyhow!("cannot determine scripts directory"))?;

            let paths = find_scripts(dir)?;
            let parsed = parse_scripts(paths);

            if let Some(config_tags) = &cfg.tags {
                let required: HashSet<&str> = config_tags.iter().map(String::as_str).collect();
                Ok(parsed
                    .into_iter()
                    .filter(|sf| {
                        sf.tags.as_ref().map_or(false, |tags| {
                            let script_tags: HashSet<&str> =
                                tags.iter().map(String::as_str).collect();
                            required.iter().all(|t| script_tags.contains(t))
                        })
                    })
                    .collect())
            } else {
                Ok(parsed)
            }
        }
    }
}

/// Parse each path in `paths` as a `ScriptFile`, silently skipping unparseable entries.
pub fn parse_scripts(paths: Vec<PathBuf>) -> Vec<ScriptFile> {
    paths.into_iter().filter_map(ScriptFile::new).collect()
}

/// Return all files found directly inside `dir` (non-recursive).
pub fn find_scripts(dir: PathBuf) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        return Err(anyhow!("scripts directory not found: {}", dir.display()));
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&dir)? {
        files.push(entry?.path());
    }
    Ok(files)
}

// ── Script ───────────────────────────────────────────────────────────────────

/// A resolved script ready to be executed against a specific IP + port set.
#[derive(Debug, Clone)]
pub struct Script {
    path: Option<PathBuf>,
    ip: IpAddr,
    open_ports: Vec<u16>,
    trigger_port: Option<String>,
    ports_separator: Option<String>,
    #[allow(dead_code)]
    tags: Option<Vec<String>>,
    call_format: Option<String>,
}

impl Script {
    pub fn build(
        path: Option<PathBuf>,
        ip: IpAddr,
        open_ports: Vec<u16>,
        trigger_port: Option<String>,
        ports_separator: Option<String>,
        tags: Option<Vec<String>>,
        call_format: Option<String>,
    ) -> Self {
        Self {
            path,
            ip,
            open_ports,
            trigger_port,
            ports_separator,
            tags,
            call_format,
        }
    }

    /// Substitute template variables and execute the script.
    ///
    /// Template variables in `call_format`:
    /// - `{{ip}}`        — target IP address
    /// - `{{port}}`      — comma-joined open ports (or trigger_port if set)
    /// - `{{ipversion}}` — `"4"` or `"6"`
    /// - `{{script}}`    — absolute path to the script file
    pub fn run(self) -> Result<String> {
        let separator = self.ports_separator.as_deref().unwrap_or(",");
        let mut ports_str = self
            .open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(separator);
        if let Some(trigger) = self.trigger_port {
            ports_str = trigger;
        }

        let call_format = self
            .call_format
            .as_deref()
            .ok_or_else(|| anyhow!("script has no call_format — cannot run"))?;

        let ip_version = match self.ip {
            IpAddr::V4(_) => "4",
            IpAddr::V6(_) => "6",
        };
        let script_path = self.path.as_deref().and_then(|p| p.to_str()).unwrap_or("");

        let to_run = call_format
            .replace("{{script}}", script_path)
            .replace("{{ip}}", &self.ip.to_string())
            .replace("{{port}}", &ports_str)
            .replace("{{ipversion}}", ip_version);

        debug!(cmd = %to_run, "executing script");
        execute_script(&to_run)
    }
}

fn execute_script(command: &str) -> Result<String> {
    let (shell, flag) = if cfg!(unix) {
        ("sh", "-c")
    } else {
        ("cmd.exe", "/c")
    };

    let output = Command::new(shell)
        .args([flag, command])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| anyhow!("failed to spawn script process: {e}"))?;

    let code = output.status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            output.status.signal().unwrap_or(1)
        }
        #[cfg(not(unix))]
        {
            1
        }
    });

    if code != 0 {
        return Err(anyhow!("script exited with non-zero code {code}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ── ScriptFile ───────────────────────────────────────────────────────────────

/// A script definition parsed from a script file's comment header.
///
/// Script files begin with a shebang (`#!`) followed by TOML key=value lines
/// prefixed with `#`. The parser reads those lines until it reaches a
/// non-comment, non-empty line.
///
/// Example script header:
/// ```sh
/// #!/usr/bin/env bash
/// # tags = ["example"]
/// # ports_separator = ","
/// # call_format = "nmap -p {{port}} {{ip}}"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ScriptFile {
    #[serde(skip)]
    pub path: Option<PathBuf>,
    pub tags: Option<Vec<String>>,
    pub developer: Option<Vec<String>>,
    pub port: Option<String>,
    pub ports_separator: Option<String>,
    pub call_format: Option<String>,
}

impl ScriptFile {
    /// Parse a script file's comment header into a `ScriptFile`.
    ///
    /// Returns `None` if the file cannot be opened or its header cannot be parsed.
    pub fn new(path: PathBuf) -> Option<Self> {
        let real_path = path.clone();
        let mut header = String::new();

        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                debug!(path = %real_path.display(), err = %e, "cannot open script file");
                return None;
            }
        };

        // Skip the first line (shebang), then collect `# key = value` lines.
        for line in io::BufReader::new(file).lines().skip(1).flatten() {
            if line.trim_start().starts_with('#') {
                let cleaned = line.trim_start_matches('#').trim().to_string();
                header.push_str(&cleaned);
                header.push('\n');
            } else {
                break;
            }
        }

        match toml::from_str::<ScriptFile>(&header) {
            Ok(mut sf) => {
                sf.path = Some(real_path);
                Some(sf)
            }
            Err(e) => {
                debug!(
                    path = %real_path.display(),
                    err = %e,
                    "cannot parse script header"
                );
                None
            }
        }
    }

    /// Convert this file definition into a runnable [`Script`] for a specific target.
    pub fn into_script(self, ip: IpAddr, open_ports: Vec<u16>) -> Script {
        Script::build(
            self.path,
            ip,
            open_ports,
            self.port,
            self.ports_separator,
            self.tags,
            self.call_format,
        )
    }
}

// ── ScriptConfig ─────────────────────────────────────────────────────────────

/// Configuration for custom script selection (`~/.rustscan_scripts.toml`).
#[derive(Debug, Deserialize)]
pub struct ScriptConfig {
    pub tags: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    pub developer: Option<Vec<String>>,
    /// Override directory where scripts are searched (default: `~/`).
    pub directory: Option<String>,
}

impl ScriptConfig {
    /// Read `~/.rustscan_scripts.toml`.
    pub fn read() -> Result<Self> {
        let path = dirs::home_dir()
            .map(|mut p| {
                p.push(".rustscan_scripts.toml");
                p
            })
            .ok_or_else(|| anyhow!("cannot determine home directory"))?;

        let content = fs::read_to_string(&path)
            .map_err(|e| anyhow!("cannot read {}: {e}", path.display()))?;

        toml::from_str(&content).map_err(|e| anyhow!("invalid TOML in script config: {e}"))
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(".rustscan_scripts")
            .join(name)
    }

    #[test]
    fn find_scripts_in_fixtures() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(".rustscan_scripts");
        if dir.exists() {
            let paths = find_scripts(dir).unwrap();
            let parsed = parse_scripts(paths);
            assert!(!parsed.is_empty());
        }
    }

    #[test]
    fn parse_txt_script_file() {
        let p = fixture("test_script.txt");
        if p.exists() {
            let sf = ScriptFile::new(p).expect("should parse");
            assert!(sf
                .tags
                .as_ref()
                .map_or(false, |t| t.contains(&"core_approved".to_string())));
            assert!(sf.call_format.is_some());
        }
    }

    #[test]
    fn template_substitution_ip_port() {
        let sf = ScriptFile {
            path: None,
            tags: None,
            developer: None,
            port: None,
            ports_separator: Some(",".into()),
            call_format: Some("echo {{ip}} {{port}} -{{ipversion}}".into()),
        };
        let script = sf.into_script("127.0.0.1".parse().unwrap(), vec![80, 443]);
        let result = script.run().unwrap();
        assert!(result.contains("127.0.0.1"));
        assert!(result.contains("80,443"));
        assert!(result.contains("-4"));
    }

    #[test]
    fn missing_call_format_returns_err() {
        let sf = ScriptFile {
            path: None,
            tags: None,
            developer: None,
            port: None,
            ports_separator: None,
            call_format: None,
        };
        let script = sf.into_script("127.0.0.1".parse().unwrap(), vec![80]);
        assert!(script.run().is_err());
    }

    #[test]
    fn trigger_port_overrides_open_ports() {
        let sf = ScriptFile {
            path: None,
            tags: None,
            developer: None,
            port: Some("9001".into()),
            ports_separator: Some(",".into()),
            call_format: Some("echo {{port}}".into()),
        };
        let script = sf.into_script("127.0.0.1".parse().unwrap(), vec![80, 443]);
        let output = script.run().unwrap();
        assert!(output.contains("9001"));
        assert!(!output.contains("80"));
    }

    #[test]
    #[cfg(unix)]
    fn run_bash_fixture() {
        let p = fixture("test_script.sh");
        if p.exists() {
            let sf = ScriptFile::new(p).unwrap();
            let script = sf.into_script("127.0.0.1".parse().unwrap(), vec![80, 8080]);
            let output = script.run().unwrap();
            assert_eq!(output.trim(), "127.0.0.1 80,8080");
        }
    }
}

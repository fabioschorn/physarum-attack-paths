//! Output writer — mirrors Nuclei's `StandardWriter` + `StatsOutputWriter`.
//!
//! Screen format (colour enabled):
//!   [template-id:matcher] [http] [severity] target:port ["extracted", ...]
//!
//! Each component maps to a Nuclei field:
//!   template-id  → ResultEvent.TemplateID   (bright-green)
//!   protocol     → ResultEvent.Type         (bright-blue)
//!   severity     → Info.Severity            (colour by level)
//!   target:port  → ResultEvent.Matched      (white)
//!   extracted    → ResultEvent.ExtractedResults (bright-cyan)

use std::{
    fs::File,
    io::{BufWriter, Write},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use physarum_sporangium::{PatternFinding, PatternProtocol, PatternTemplate, SeverityHint};

// ── ANSI colour codes ─────────────────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREEN_BRIGHT: &str = "\x1b[92m";
const BLUE_BRIGHT: &str = "\x1b[94m";
const CYAN: &str = "\x1b[36m";
const CYAN_BRIGHT: &str = "\x1b[96m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RED_BRIGHT: &str = "\x1b[91m";
const WHITE: &str = "\x1b[97m";
const GREY: &str = "\x1b[90m";

// ─────────────────────────────────────────────────────────────────────────────

/// Level tag for log-style prefix lines ([INF] / [WRN] / [ERR] / [VRB]).
#[derive(Clone, Copy)]
enum Level {
    Info,
    Warn,
    Error,
    Verbose,
}

// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe output writer shared across all scanner tasks.
///
/// Wraps an optional file sink alongside stdout; both receive findings.
/// Mutexed so concurrent tasks can call `write_finding` without races.
pub struct OutputWriter {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    pub silent: bool,
    pub verbose: bool,
    pub json: bool,
    pub no_color: bool,
    /// Optional file sink (append, not truncate).
    file: Option<BufWriter<File>>,
}

impl OutputWriter {
    pub fn new(
        silent: bool,
        verbose: bool,
        json: bool,
        no_color: bool,
        output_path: Option<&std::path::Path>,
    ) -> anyhow::Result<Self> {
        let file = output_path
            .map(|p| {
                File::create(p)
                    .map(BufWriter::new)
                    .map_err(|e| anyhow::anyhow!("cannot open output file {}: {e}", p.display()))
            })
            .transpose()?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                silent,
                verbose,
                json,
                no_color,
                file,
            })),
        })
    }

    // ── public API ────────────────────────────────────────────────────────────

    pub fn print_banner(&self) {
        let g = self.inner.lock().unwrap();
        if g.silent {
            return;
        }
        let line = format!(
            "{}physarum-spore{} v{} — Nuclei-inspired HTTP pattern scanner",
            if g.no_color { "" } else { GREEN_BRIGHT },
            if g.no_color { "" } else { RESET },
            env!("CARGO_PKG_VERSION"),
        );
        println!("{line}");
        println!(
            "{}Use responsibly: lab/owned environments only.{}",
            if g.no_color { "" } else { GREY },
            if g.no_color { "" } else { RESET },
        );
        println!();
    }

    pub fn print_scan_info(&self, targets: usize, ports: usize, templates: usize) {
        let g = self.inner.lock().unwrap();
        if g.silent {
            return;
        }
        g.log(
            Level::Info,
            &format!(
                "Targets: {targets} | Ports: {ports} | Templates: {templates} | Total probes: {}",
                targets * ports * templates,
            ),
        );
    }

    /// Called in verbose mode before each HTTP probe.
    pub fn print_probe_start(&self, template_id: &str, ip: IpAddr, port: u16) {
        let g = self.inner.lock().unwrap();
        if !g.verbose || g.silent {
            return;
        }
        g.log(
            Level::Verbose,
            &format!("{} → {}:{}", g.color(template_id, GREY), ip, port),
        );
    }

    /// Called when a template probe fails (network error / timeout).
    pub fn print_probe_error(&self, template_id: &str, ip: IpAddr, port: u16, err: &anyhow::Error) {
        let g = self.inner.lock().unwrap();
        if g.silent {
            return;
        }
        if g.verbose {
            g.log(
                Level::Warn,
                &format!("{template_id} → {ip}:{port} — {err:#}"),
            );
        }
    }

    /// Write one `PatternFinding` to stdout (and file if configured).
    pub fn write_finding(&self, finding: &PatternFinding) {
        let mut g = self.inner.lock().unwrap();
        let line = if g.json {
            format_json(finding)
        } else {
            format_screen(finding, g.no_color)
        };

        println!("{line}");

        if let Some(ref mut fw) = g.file {
            // File always receives plain JSON for structured post-processing.
            let json_line = format_json(finding);
            let _ = writeln!(fw, "{json_line}");
        }
    }

    pub fn print_stats(
        &self,
        targets: usize,
        templates: usize,
        requests: usize,
        matches: usize,
        errors: usize,
        duration: Duration,
    ) {
        let g = self.inner.lock().unwrap();
        if g.silent {
            return;
        }
        g.log(
            Level::Info,
            &format!(
                "Targets: {targets} | Templates: {templates} | \
                 Requests: {requests} | Matches: {} | Errors: {errors} | \
                 Duration: {:.2}s",
                g.color(
                    &matches.to_string(),
                    if matches > 0 { GREEN_BRIGHT } else { WHITE }
                ),
                duration.as_secs_f64(),
            ),
        );
    }

    pub fn print_info(&self, msg: &str) {
        let g = self.inner.lock().unwrap();
        if g.silent {
            return;
        }
        g.log(Level::Info, msg);
    }

    pub fn print_error(&self, msg: &str) {
        let g = self.inner.lock().unwrap();
        g.log(Level::Error, msg);
    }

    /// List-templates output: one line per template.
    pub fn print_template_list(&self, templates: &[PatternTemplate]) {
        let g = self.inner.lock().unwrap();
        for t in templates {
            let sev = severity_str(t.info.severity, g.no_color);
            let tags = t.info.tags.join(", ");
            println!(
                "[{}] [{}] [{}] {}",
                g.color(&t.id, GREEN_BRIGHT),
                g.color("http", BLUE_BRIGHT),
                sev,
                g.color(&tags, GREY),
            );
        }
    }
}

// ── Inner helpers ─────────────────────────────────────────────────────────────

impl Inner {
    fn color(&self, s: &str, code: &str) -> String {
        if self.no_color {
            s.to_string()
        } else {
            format!("{code}{s}{RESET}")
        }
    }

    fn log(&self, level: Level, msg: &str) {
        let prefix = if self.no_color {
            match level {
                Level::Info => "[INF]".into(),
                Level::Warn => "[WRN]".into(),
                Level::Error => "[ERR]".into(),
                Level::Verbose => "[VRB]".into(),
            }
        } else {
            match level {
                Level::Info => format!("{CYAN}[INF]{RESET}"),
                Level::Warn => format!("{YELLOW}[WRN]{RESET}"),
                Level::Error => format!("{RED}[ERR]{RESET}"),
                Level::Verbose => format!("{GREY}[VRB]{RESET}"),
            }
        };

        // Errors go to stderr; everything else to stdout.
        match level {
            Level::Error => eprintln!("{prefix} {msg}"),
            _ => println!("{prefix} {msg}"),
        }
    }
}

// ── formatting ────────────────────────────────────────────────────────────────

/// Nuclei-style screen line:
///   [template-id] [http] [severity] 172.20.0.3:80 ["nginx/1.25.3"]
fn format_screen(f: &PatternFinding, no_color: bool) -> String {
    let color = |s: &str, code: &str| -> String {
        if no_color {
            s.to_string()
        } else {
            format!("{code}{s}{RESET}")
        }
    };

    let proto = match f.protocol {
        PatternProtocol::Http => "http",
        PatternProtocol::Tcp => "tcp",
        PatternProtocol::Dns => "dns",
        PatternProtocol::Ssl => "ssl",
        PatternProtocol::WebSocket => "websocket",
    };

    let sev = severity_str(f.severity_hint, no_color);

    // Flatten all extracted values across all facts.
    let extracted: Vec<String> = f
        .extracted_facts
        .iter()
        .flat_map(|fact| fact.values.iter().cloned())
        .collect();

    let mut line = format!(
        "[{}] [{}] [{}] {}:{}",
        color(&f.template_id, GREEN_BRIGHT),
        color(proto, BLUE_BRIGHT),
        sev,
        color(&f.target_ip.to_string(), WHITE),
        f.port,
    );

    if !extracted.is_empty() {
        let vals = extracted
            .iter()
            .map(|v| format!("\"{}\"", v.trim()))
            .collect::<Vec<_>>()
            .join(", ");
        line.push_str(&format!(" [{}]", color(&vals, CYAN_BRIGHT)));
    }

    line
}

/// Compact JSON line — one object per finding, suitable for jq/grep pipelines.
fn format_json(f: &PatternFinding) -> String {
    // Build a simplified view: avoid re-exporting internal fields.
    let extracted: Vec<String> = f
        .extracted_facts
        .iter()
        .flat_map(|fact| fact.values.iter().cloned())
        .collect();

    let obj = serde_json::json!({
        "template_id":   f.template_id,
        "name":          f.name,
        "target":        f.target_ip.to_string(),
        "port":          f.port,
        "severity":      format!("{:?}", f.severity_hint).to_lowercase(),
        "protocol":      match f.protocol {
            PatternProtocol::Http => "http",
            PatternProtocol::Tcp => "tcp",
            PatternProtocol::Dns => "dns",
            PatternProtocol::Ssl => "ssl",
            PatternProtocol::WebSocket => "websocket",
        },
        "matched":       f.matched_condition_summary,
        "extracted":     extracted,
        "confidence":    f.confidence,
        "timestamp":     f.timestamp.to_rfc3339(),
    });

    obj.to_string()
}

fn severity_str(s: SeverityHint, no_color: bool) -> String {
    let (label, code) = match s {
        SeverityHint::Info => ("info", CYAN),
        SeverityHint::Low => ("low", WHITE),
        SeverityHint::Medium => ("medium", YELLOW),
        SeverityHint::High => ("high", RED),
        SeverityHint::Critical => ("critical", RED_BRIGHT),
        SeverityHint::Unknown => ("unknown", GREY),
    };

    if no_color {
        label.into()
    } else if s == SeverityHint::Critical {
        format!("{BOLD}{code}{label}{RESET}")
    } else {
        format!("{code}{label}{RESET}")
    }
}

// ── I/O flush on drop ─────────────────────────────────────────────────────────

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(ref mut fw) = self.file {
            let _ = fw.flush();
        }
    }
}

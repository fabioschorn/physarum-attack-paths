//! `physarum-spore` — Nuclei-inspired HTTP pattern scanner.
//!
//! Capabilities ported from Nuclei (Go) to this binary:
//!   -u / -list        single target or file-based target list
//!   -p / -port        one or more ports to probe (default: 80)
//!   -id               run specific template(s) by ID
//!   -tags             filter templates by tag
//!   -severity         filter templates by severity level
//!   -exclude-id       exclude template(s) by ID
//!   -exclude-tags     exclude templates by tag
//!   -exclude-severity exclude templates by severity level
//!   -o / -output      write findings to file (JSON, one per line)
//!   -json             emit JSON to stdout instead of coloured text
//!   -silent           suppress all output except findings
//!   -v / -verbose     show every probe attempt before results
//!   -nc / -no-color   disable ANSI colour codes
//!   -c                max concurrent probes (default: 25)
//!   -timeout          HTTP request timeout in ms (default: 5 000)
//!   -rl / -rate-limit approximate requests/second (default: 150)
//!   -tl               list available built-in templates and exit
//!   -stats            print stats summary after scan

mod filter;
mod output;

use std::{
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::{self, StreamExt};
use physarum_sporangium::{PatternRunner, PatternTemplate, RunPolicy};
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;

use crate::filter::{parse_list, parse_severities, TemplateFilter};
use crate::output::OutputWriter;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "physarum-spore",
    version,
    max_term_width = 120,
    about = "Nuclei-inspired HTTP pattern scanner (physarum evidence enrichment layer)",
    long_about = "\
physarum-spore runs built-in detection templates against HTTP targets.\n\
It is the CLI front-end for the physarum-sporangium evidence enrichment library.\n\
\n\
Template families (21 built-in):\n\
  server    — nginx, Apache, IIS, lighttpd, Caddy, OpenResty\n\
  tech      — PHP, ASP.NET, Node/Express\n\
  status    — HTTP 200 OK, redirect, 401, 403\n\
  content   — JSON API, page-title extraction\n\
  info      — server version exposure\n\
  default   — default nginx/Apache welcome pages\n\
  security  — missing X-Frame-Options, HSTS, CSP\n\
\n\
Use only in owned, local, Docker, or AWS lab environments.\
"
)]
struct Cli {
    // ── target input ──────────────────────────────────────────────────────────
    /// Target IP(s): comma-separated, or repeated. Format: IP or IP:PORT
    #[arg(
        short = 'u',
        long = "target",
        value_delimiter = ',',
        value_name = "IP[,IP…]"
    )]
    targets: Vec<String>,

    /// File with one target per line (IP or IP:PORT)
    #[arg(
        short = 'l',
        long = "list",
        value_name = "FILE",
        conflicts_with = "targets"
    )]
    target_list: Option<PathBuf>,

    // ── port ──────────────────────────────────────────────────────────────────
    /// Port(s) to probe: comma-separated (default: 80)
    #[arg(
        short = 'p',
        long = "port",
        value_delimiter = ',',
        value_name = "PORT[,PORT…]",
        default_value = "80"
    )]
    ports: Vec<u16>,

    // ── template include filters ───────────────────────────────────────────────
    /// Run only these template IDs (comma-separated)
    #[arg(long = "id", value_name = "ID[,ID…]")]
    id: Option<String>,

    /// Include only templates with any of these tags (comma-separated)
    #[arg(long = "tags", value_name = "TAG[,TAG…]")]
    tags: Option<String>,

    /// Include only templates at these severity levels (info,low,medium,high,critical)
    #[arg(long = "severity", value_name = "LEVEL[,LEVEL…]")]
    severity: Option<String>,

    // ── template exclude filters ───────────────────────────────────────────────
    /// Exclude these template IDs (comma-separated)
    #[arg(long = "exclude-id", value_name = "ID[,ID…]")]
    exclude_id: Option<String>,

    /// Exclude templates with any of these tags (comma-separated)
    #[arg(long = "exclude-tags", value_name = "TAG[,TAG…]")]
    exclude_tags: Option<String>,

    /// Exclude templates at these severity levels
    #[arg(long = "exclude-severity", value_name = "LEVEL[,LEVEL…]")]
    exclude_severity: Option<String>,

    // ── output ────────────────────────────────────────────────────────────────
    /// Write findings to file (JSON lines, one per finding)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Emit JSON to stdout instead of coloured text
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Suppress all output except findings
    #[arg(short = 's', long = "silent")]
    silent: bool,

    /// Show every probe attempt (verbose mode)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Disable ANSI colour codes
    #[arg(long = "no-color", alias = "nc")]
    no_color: bool,

    // ── execution ─────────────────────────────────────────────────────────────
    /// Maximum concurrent HTTP probes (default: 25)
    #[arg(
        short = 'c',
        long = "concurrency",
        default_value_t = 25,
        value_name = "N"
    )]
    concurrency: usize,

    /// HTTP request timeout in milliseconds (default: 5000)
    #[arg(long = "timeout", default_value_t = 5_000, value_name = "MS")]
    timeout_ms: u64,

    /// Maximum redirects to follow per request (default: 3)
    #[arg(long = "max-redirects", default_value_t = 3u8, value_name = "N")]
    max_redirects: u8,

    /// Approximate requests per second — limits via inter-request sleep (default: 150)
    #[arg(
        long = "rate-limit",
        alias = "rl",
        default_value_t = 150,
        value_name = "N"
    )]
    rate_limit: u64,

    // ── info ──────────────────────────────────────────────────────────────────
    /// List all available built-in templates and exit
    #[arg(long = "list-templates", alias = "tl")]
    list_templates: bool,

    /// Print statistics summary after the scan
    #[arg(long = "stats")]
    stats: bool,
}

// ── target parsing ────────────────────────────────────────────────────────────

/// `"172.20.0.3"` → `(172.20.0.3, None)`
/// `"172.20.0.3:8080"` → `(172.20.0.3, Some(8080))`
fn parse_target_str(s: &str) -> Result<(IpAddr, Option<u16>)> {
    let s = s.trim();
    // Try IP:PORT first (SocketAddrV4 covers IPv4; handle IPv6 brackets too)
    if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        return Ok((sock.ip(), Some(sock.port())));
    }
    // Bare IP
    let ip = IpAddr::from_str(s)
        .with_context(|| format!("cannot parse target '{s}' — expected IP or IP:PORT"))?;
    Ok((ip, None))
}

fn load_targets(cli: &Cli) -> Result<Vec<(IpAddr, Option<u16>)>> {
    let raw: Vec<String> = if let Some(ref path) = cli.target_list {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read target list '{}'", path.display()))?;
        content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        cli.targets.clone()
    };

    if raw.is_empty() {
        anyhow::bail!("no targets — use -u/--target or -l/--list");
    }

    raw.iter()
        .map(|s| parse_target_str(s))
        .collect::<Result<Vec<_>>>()
}

// ── scan task ─────────────────────────────────────────────────────────────────

struct Task {
    ip: IpAddr,
    port: u16,
    template: PatternTemplate,
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    // ── output writer ─────────────────────────────────────────────────────────
    let writer = Arc::new(OutputWriter::new(
        cli.silent,
        cli.verbose,
        cli.json,
        cli.no_color,
        cli.output.as_deref(),
    )?);

    writer.print_banner();

    // ── template catalog + filters ────────────────────────────────────────────
    let all = physarum_sporangium::all_templates();

    if cli.list_templates {
        let filter = build_filter(&cli);
        let visible = filter.apply(all);
        writer.print_info(&format!("{} built-in templates:", visible.len()));
        writer.print_template_list(&visible);
        return Ok(());
    }

    let filter = build_filter(&cli);
    let templates = filter.apply(all);

    if templates.is_empty() {
        writer.print_error("no templates matched the provided filters");
        std::process::exit(1);
    }

    // ── targets ───────────────────────────────────────────────────────────────
    let raw_targets = load_targets(&cli)?;
    let ports = cli.ports.clone();

    // Expand: (ip, opt_port) × ports → (ip, effective_port)
    // A port embedded in the target string overrides the -p list.
    let effective_targets: Vec<(IpAddr, u16)> = raw_targets
        .into_iter()
        .flat_map(|(ip, opt_port)| {
            if let Some(p) = opt_port {
                vec![(ip, p)]
            } else {
                ports.iter().map(|&p| (ip, p)).collect()
            }
        })
        .collect();

    writer.print_scan_info(effective_targets.len(), cli.ports.len(), templates.len());

    // ── runner ────────────────────────────────────────────────────────────────
    let allowed_ids: Vec<String> = templates.iter().map(|t| t.id.clone()).collect();
    let policy = RunPolicy {
        allowed_check_ids: allowed_ids,
        max_response_bytes: 65_536,
        request_timeout_ms: cli.timeout_ms,
        max_redirects: cli.max_redirects,
    };
    let runner = Arc::new(PatternRunner::new(policy)?);

    // ── build task list ───────────────────────────────────────────────────────
    let tasks: Vec<Task> = effective_targets
        .iter()
        .flat_map(|&(ip, port)| {
            templates.iter().map(move |t| Task {
                ip,
                port,
                template: t.clone(),
            })
        })
        .collect();

    let total_requests = tasks.len();

    // ── concurrency + rate limiting ───────────────────────────────────────────
    let semaphore = Arc::new(Semaphore::new(cli.concurrency));
    // Minimum interval between consecutive request starts (µs → Duration).
    let rate_delay = 1_000_000u64
        .checked_div(cli.rate_limit)
        .map(std::time::Duration::from_micros)
        .unwrap_or(std::time::Duration::ZERO);

    // Counters for stats
    let completed = Arc::new(AtomicUsize::new(0));
    let matches = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    let start = Instant::now();

    // ── execute ───────────────────────────────────────────────────────────────
    stream::iter(tasks)
        .map(|task| {
            let runner = runner.clone();
            let writer = writer.clone();
            let sem = semaphore.clone();
            let matches = matches.clone();
            let errors = errors.clone();
            let completed = completed.clone();

            async move {
                let _permit = sem.acquire().await.expect("semaphore closed");

                // Rate limit: sleep before each probe so we don't exceed r/s budget.
                if !rate_delay.is_zero() {
                    tokio::time::sleep(rate_delay).await;
                }

                writer.print_probe_start(&task.template.id, task.ip, task.port);

                match runner.run(&task.template, task.ip, task.port).await {
                    Ok(findings) => {
                        for f in &findings {
                            matches.fetch_add(1, Ordering::Relaxed);
                            writer.write_finding(f);
                        }
                    }
                    Err(e) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        writer.print_probe_error(&task.template.id, task.ip, task.port, &e);
                    }
                }

                completed.fetch_add(1, Ordering::Relaxed);
            }
        })
        .buffer_unordered(cli.concurrency)
        .for_each(|()| async {})
        .await;

    // ── stats ─────────────────────────────────────────────────────────────────
    if cli.stats || !cli.silent {
        writer.print_stats(
            effective_targets.len(),
            templates.len(),
            total_requests,
            matches.load(Ordering::Relaxed),
            errors.load(Ordering::Relaxed),
            start.elapsed(),
        );
    }

    Ok(())
}

// ── filter builder ────────────────────────────────────────────────────────────

fn build_filter(cli: &Cli) -> TemplateFilter {
    TemplateFilter {
        ids: cli.id.as_deref().map(parse_list).unwrap_or_default(),
        tags: cli.tags.as_deref().map(parse_list).unwrap_or_default(),
        severities: cli
            .severity
            .as_deref()
            .map(parse_severities)
            .unwrap_or_default(),
        exclude_ids: cli
            .exclude_id
            .as_deref()
            .map(parse_list)
            .unwrap_or_default(),
        exclude_tags: cli
            .exclude_tags
            .as_deref()
            .map(parse_list)
            .unwrap_or_default(),
        exclude_severities: cli
            .exclude_severity
            .as_deref()
            .map(parse_severities)
            .unwrap_or_default(),
    }
}

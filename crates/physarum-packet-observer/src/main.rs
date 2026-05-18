use anyhow::Result;
use clap::Parser;

mod config;
// mapper and submitter are consumed by observer.rs (Linux only);
// suppress dead_code on other platforms where observer.rs is excluded.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod mapper;
mod observer;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod submitter;

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level)),
        )
        .init();

    tracing::info!(
        agent_id    = %config.agent_id,
        coordinator = %config.coordinator_url,
        interface   = %config.interface,
        dry_run     = config.dry_run,
        "physarum-packet-observer starting"
    );

    run(&config).await
}

#[cfg(target_os = "linux")]
async fn run(config: &Config) -> Result<()> {
    observer::run(config).await
}

#[cfg(not(target_os = "linux"))]
async fn run(_config: &Config) -> Result<()> {
    anyhow::bail!(
        "eBPF packet observation requires Linux; this binary was built for {}. \
         Cross-compile for x86_64-unknown-linux-gnu or run on AWS EC2 (AL2023).",
        std::env::consts::OS
    )
}

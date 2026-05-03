use axum::{routing::get, Json, Router};
use chrono::Utc;
use clap::Parser;
use physarum_protocol::{PeerInfo, ProbeReport, RegisterRequest};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Clone)]
#[command(name = "physarum-agent", about = "Physarum attack-path agent")]
struct Cli {
    #[arg(long, env = "PHYSARUM_AGENT_ID")]
    id: String,

    #[arg(long, env = "PHYSARUM_COORDINATOR")]
    coordinator: String,

    #[arg(long, env = "PHYSARUM_LISTEN")]
    listen: SocketAddr,

    #[arg(long, env = "PHYSARUM_ADVERTISE_ADDRESS")]
    advertise_address: String,

    #[arg(long, default_value = "10", env = "PHYSARUM_PROBE_INTERVAL_SECONDS")]
    probe_interval_seconds: u64,
}

#[derive(serde::Serialize)]
struct ProbeResponse {
    agent_id: String,
    status: &'static str,
}

fn build_probe_router(agent_id: Arc<String>) -> Router {
    Router::new().route(
        "/probe",
        get(move || {
            let id = agent_id.clone();
            async move {
                Json(ProbeResponse {
                    agent_id: id.as_ref().clone(),
                    status: "ok",
                })
            }
        }),
    )
}

async fn register(cli: &Cli, client: &reqwest::Client) -> Result<(), reqwest::Error> {
    let req = build_register_request(cli);
    client
        .post(format!("{}/register", cli.coordinator))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;
    tracing::info!(agent_id = %cli.id, coordinator = %cli.coordinator, "registered with coordinator");
    Ok(())
}

fn build_register_request(cli: &Cli) -> RegisterRequest {
    RegisterRequest {
        agent_id: cli.id.clone(),
        address: cli.advertise_address.clone(),
        probe_port: cli.listen.port(),
    }
}

async fn fetch_peers(cli: &Cli, client: &reqwest::Client) -> Result<Vec<PeerInfo>, reqwest::Error> {
    let peers = client
        .get(format!("{}/peers/{}", cli.coordinator, cli.id))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<PeerInfo>>()
        .await?;
    Ok(peers)
}

fn build_peer_probe_url(peer: &PeerInfo) -> String {
    format!("http://{}:{}/probe", peer.address, peer.probe_port)
}

async fn probe_peer(client: &reqwest::Client, url: &str) -> (bool, Option<u64>) {
    let start = Instant::now();
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let rtt_ms = start.elapsed().as_millis() as u64;
            (true, Some(rtt_ms))
        }
        _ => (false, None),
    }
}

fn build_probe_report(
    source: &str,
    peer: &PeerInfo,
    success: bool,
    rtt_ms: Option<u64>,
) -> ProbeReport {
    ProbeReport {
        source: source.to_string(),
        target: peer.agent_id.clone(),
        success,
        rtt_ms,
        observed_at: Utc::now(),
    }
}

async fn send_report(
    cli: &Cli,
    client: &reqwest::Client,
    report: &ProbeReport,
) -> Result<(), reqwest::Error> {
    client
        .post(format!("{}/report", cli.coordinator))
        .json(report)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn probe_loop(cli: Arc<Cli>, client: Arc<reqwest::Client>) {
    let interval = Duration::from_secs(cli.probe_interval_seconds);
    loop {
        match fetch_peers(&cli, &client).await {
            Ok(peers) => {
                tracing::debug!(count = peers.len(), "fetched peers");
                for peer in &peers {
                    let url = build_peer_probe_url(peer);
                    let (success, rtt_ms) = probe_peer(&client, &url).await;
                    tracing::info!(
                        target = %peer.agent_id,
                        success,
                        rtt_ms = ?rtt_ms,
                        "probe result"
                    );
                    let report = build_probe_report(&cli.id, peer, success, rtt_ms);
                    if let Err(e) = send_report(&cli, &client, &report).await {
                        tracing::warn!(error = %e, "failed to send report");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to fetch peers"),
        }
        tokio::time::sleep(interval).await;
    }
}

#[tokio::main]
async fn main() {
    let cli = Arc::new(Cli::parse());

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client"),
    );

    let probe_app = build_probe_router(Arc::new(cli.id.clone()));
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .expect("failed to bind probe listener");
    tracing::info!(listen = %cli.listen, agent_id = %cli.id, "probe server listening");

    tokio::spawn(async move {
        axum::serve(listener, probe_app).await.unwrap();
    });

    if let Err(e) = register(&cli, &client).await {
        tracing::error!(error = %e, "registration failed; aborting");
        std::process::exit(1);
    }

    probe_loop(cli, client).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use physarum_protocol::PeerInfo;

    fn test_cli() -> Cli {
        Cli {
            id: "agent-b".to_string(),
            coordinator: "http://127.0.0.1:8080".to_string(),
            listen: "127.0.0.1:9001".parse().unwrap(),
            advertise_address: "127.0.0.1".to_string(),
            probe_interval_seconds: 10,
        }
    }

    fn test_peer() -> PeerInfo {
        PeerInfo {
            agent_id: "agent-c".to_string(),
            address: "127.0.0.1".to_string(),
            probe_port: 9002,
        }
    }

    #[test]
    fn register_request_fields() {
        let cli = test_cli();
        let req = build_register_request(&cli);
        assert_eq!(req.agent_id, "agent-b");
        assert_eq!(req.address, "127.0.0.1");
        assert_eq!(req.probe_port, 9001);
    }

    #[test]
    fn peer_probe_url_format() {
        let peer = test_peer();
        let url = build_peer_probe_url(&peer);
        assert_eq!(url, "http://127.0.0.1:9002/probe");
    }

    #[test]
    fn probe_report_success() {
        let cli = test_cli();
        let peer = test_peer();
        let report = build_probe_report(&cli.id, &peer, true, Some(7));
        assert_eq!(report.source, "agent-b");
        assert_eq!(report.target, "agent-c");
        assert!(report.success);
        assert_eq!(report.rtt_ms, Some(7));
    }

    #[test]
    fn probe_report_failure() {
        let cli = test_cli();
        let peer = test_peer();
        let report = build_probe_report(&cli.id, &peer, false, None);
        assert!(!report.success);
        assert_eq!(report.rtt_ms, None);
    }
}
